"""Views for user registration and ECP authentication."""

from __future__ import annotations

import logging

from django.contrib import messages
from django.contrib.auth import authenticate, get_user_model, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
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

        derived_key, _ = derive_key_from_password(password.encode('utf-8'))
        private_key_pem, public_key_pem = generate_key_pair(password=derived_key)

        user = User.objects.create_user(username=username, email=form.cleaned_data.get('email', ''), password=password)
        user.public_key = public_key_pem
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
