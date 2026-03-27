"""Views for user registration and ECP authentication."""

from __future__ import annotations

import logging

from django.contrib import messages
from django.contrib.auth import authenticate, get_user_model, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.views import View
from django.views.generic import FormView, TemplateView

from django_ecp_auth.utils.crypto_utils import derive_key_from_password, generate_key_pair

from users.forms import LoginStep1Form, RegisterForm

logger = logging.getLogger(__name__)
User = get_user_model()


class RegisterView(FormView):
    """CBV for user registration with ECP keypair generation.

    GET: Show registration form.
    POST: Create user, generate EC keypair, store private key in session
          for one-time download, redirect to success page.

    The private key is NEVER stored in DB.

    Example:
        path('register/', RegisterView.as_view(), name='register'),
    """

    template_name = 'auth/register.html'
    form_class = RegisterForm

    def form_valid(self, form: RegisterForm) -> HttpResponse:
        """Create user and generate ECP keypair.

        Args:
            form: Validated RegisterForm.

        Returns:
            Redirect to register-success page.
        """
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']

        derived_key, salt = derive_key_from_password(password.encode('utf-8'))
        private_key_pem, public_key_pem = generate_key_pair(password=derived_key)

        user = User.objects.create_user(username=username, email=form.cleaned_data.get('email', ''), password=password)
        user.public_key = public_key_pem
        user.key_salt = salt
        user.save()

        logger.info('New user registered with ECP key: pk=%s', user.pk)

        self.request.session['registration_private_key_pem'] = private_key_pem
        self.request.session['registration_username'] = username
        self.request.session.set_expiry(10 * 60)

        return redirect('register-success')


class RegisterSuccessView(TemplateView):
    """Show registration success with one-time download link.

    Example:
        path('register/success/', RegisterSuccessView.as_view(), name='register-success'),
    """

    template_name = 'auth/register_success.html'

    def get_context_data(self, **kwargs) -> dict:
        """Add username to template context.

        Returns:
            Context with username from session.
        """
        context = super().get_context_data(**kwargs)
        context['username'] = self.request.session.get('registration_username', '')
        return context


class DownloadPrivateKeyView(View):
    """Serve private key as file attachment once, then remove from session.

    Example:
        path('register/private-key.pem', DownloadPrivateKeyView.as_view(), name='download-private-key'),
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        """Download private key and remove it from session.

        Args:
            request: HTTP request with session.

        Returns:
            File download response or redirect if key expired.
        """
        private_key_pem = request.session.get('registration_private_key_pem')
        username = request.session.get('registration_username', 'user')

        if not private_key_pem:
            messages.error(request, 'Приватний ключ більше недоступний. Зареєструйтесь знову.')
            return redirect('register')

        request.session.pop('registration_private_key_pem', None)

        filename_safe = ''.join(ch if ch.isalnum() else '_' for ch in username) or 'user'
        filename = f'{filename_safe}_private_key.pem'

        response = HttpResponse(private_key_pem, content_type='application/x-pem-file; charset=utf-8')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        response['Cache-Control'] = 'no-store, max-age=0'
        response['Pragma'] = 'no-cache'
        response['X-Content-Type-Options'] = 'nosniff'
        return response


class LoginStep1View(FormView):
    """CBV for step 1 of login — username and password.

    Stores user pk in session and redirects to ECP step.

    Example:
        path('login/', LoginStep1View.as_view(), name='login'),
    """

    template_name = 'auth/login.html'
    form_class = LoginStep1Form

    def dispatch(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        """Redirect authenticated users to dashboard.

        Args:
            request: HTTP request.
            *args: Positional arguments.
            **kwargs: Keyword arguments.

        Returns:
            Redirect to dashboard if authenticated, else normal dispatch.
        """
        if request.user.is_authenticated:
            return redirect('dashboard')
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form: LoginStep1Form) -> HttpResponse:
        """Authenticate and store pending user in session.

        Args:
            form: Validated LoginStep1Form.

        Returns:
            Redirect to ECP login or form with error.
        """
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']

        user = authenticate(self.request, username=username, password=password)

        if user is None:
            messages.error(self.request, 'Невірний логін або пароль.')
            return self.form_invalid(form)

        self.request.session['partial_auth_user_id'] = user.pk
        logger.info('Step 1 login success for %s', username)
        return redirect('ecp-login')


class LogoutView(View):
    """CBV for user logout.

    Example:
        path('logout/', LogoutView.as_view(), name='logout'),
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        """Logout and redirect to login.

        Args:
            request: HTTP request.

        Returns:
            Redirect to login page.
        """
        logout(request)
        return redirect('login')


class DashboardView(LoginRequiredMixin, TemplateView):
    """CBV for authenticated user dashboard.

    Example:
        path('dashboard/', DashboardView.as_view(), name='dashboard'),
    """

    template_name = 'dashboard.html'
    login_url = 'login'


import io
import zipfile
import base64
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

from users.forms import SignForm

SIGNED_DATA = b"ecp_login_challenge_v1"


def _decrypt_private_key(encrypted_pem: str, derived_key: bytes) -> ec.EllipticCurvePrivateKey:
    """Decrypt AES-GCM encrypted private key PEM.

    Args:
        encrypted_pem: PEM string with custom AES-GCM encryption.
        derived_key: 32-byte key derived via PBKDF2.

    Returns:
        Decrypted EC private key object.

    Raises:
        ValueError: If decryption fails or key format is invalid.
    """
    lines = encrypted_pem.strip().splitlines()
    b64_data = "".join(
        line for line in lines
        if not line.startswith("-----")
    )
    raw = base64.b64decode(b64_data)
    nonce = raw[:12]
    ciphertext = raw[12:]
    aesgcm = AESGCM(derived_key)
    private_pem = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return serialization.load_pem_private_key(private_pem, password=None)


def _generate_self_signed_cert(
    private_key: ec.EllipticCurvePrivateKey,
    username: str,
) -> bytes:
    """Generate self-signed X.509 DER certificate.

    Args:
        private_key: EC private key to sign the certificate with.
        username: Username to use as certificate CN.

    Returns:
        DER-encoded certificate bytes.
    """
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.SERIAL_NUMBER, "1234567890"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _sign_data(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """Sign data using EC private key with ECDSA SHA256.

    Args:
        private_key: EC private key for signing.
        data: Raw bytes to sign.

    Returns:
        DER-encoded ECDSA signature bytes.
    """
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


class SignDataView(View):
    """Sign login challenge with user private key, return files as zip.

    GET: Show sign form where user uploads private key and enters password.
    POST: Decrypt private key, generate certificate, sign challenge data,
          return zip with certificate.cer, signature.bin, signed_data.bin.

    Example:
        path("sign/", SignDataView.as_view(), name="sign"),
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        """Render sign form.

        Args:
            request: HTTP GET request.

        Returns:
            Rendered sign page with empty form.
        """
        return render(request, "auth/sign.html", {"form": SignForm()})

    def post(self, request: HttpRequest) -> HttpResponse:
        """Process private key and generate ECP files zip.

        Args:
            request: HTTP POST with private_key_file, username, password.

        Returns:
            Zip file with certificate.cer, signature.bin, signed_data.bin
            or form with error message on failure.
        """
        form = SignForm(request.POST, request.FILES)
        if not form.is_valid():
            return render(request, "auth/sign.html", {"form": form})

        username = form.cleaned_data["username"]
        password = form.cleaned_data["password"]
        private_key_file = form.cleaned_data["private_key_file"]

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            messages.error(request, "Користувача не знайдено.")
            return render(request, "auth/sign.html", {"form": form})

        try:
            salt = bytes(user.key_salt)
            if not salt:
                messages.error(request, "Ключ не налаштований для цього користувача.")
                return render(request, "auth/sign.html", {"form": form})

            derived_key, _ = derive_key_from_password(
                password.encode("utf-8"), salt=salt
            )

            encrypted_pem = private_key_file.read().decode("ascii")
            private_key = _decrypt_private_key(encrypted_pem, derived_key)

            cert_bytes = _generate_self_signed_cert(private_key, username)
            signature = _sign_data(private_key, SIGNED_DATA)

            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("certificate.cer", cert_bytes)
                zf.writestr("signature.bin", signature)
                zf.writestr("signed_data.bin", SIGNED_DATA)
            zip_buffer.seek(0)

            response = HttpResponse(
                zip_buffer.getvalue(),
                content_type="application/zip",
            )
            safe_name = "".join(c if c.isalnum() else "_" for c in username)
            response["Content-Disposition"] = (
                f'attachment; filename="{safe_name}_ecp_files.zip"'
            )
            response["Cache-Control"] = "no-store, max-age=0"
            logger.info("ECP sign files generated for user: %s", username)
            return response

        except Exception as exc:
            logger.warning("Sign failed for %s: %s", username, exc)
            messages.error(request, f"Помилка підпису: {exc}")
            return render(request, "auth/sign.html", {"form": form})
