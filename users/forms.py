"""Forms for user registration and ECP authentication."""

from __future__ import annotations

from django import forms
from django.contrib.auth.password_validation import validate_password

from .models import User


class RegisterForm(forms.ModelForm):
    """Form for user registration."""

    email = forms.EmailField(label="Email")
    password = forms.CharField(widget=forms.PasswordInput, label="Пароль")
    password_confirm = forms.CharField(widget=forms.PasswordInput, label="Підтвердіть пароль")

    class Meta:
        model = User
        fields = ["username", "email"]

    def clean(self) -> dict:
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        password_confirm = cleaned_data.get("password_confirm")
        if password and password_confirm and password != password_confirm:
            raise forms.ValidationError("Паролі не співпадають.")
        if password:
            validate_password(password)
        return cleaned_data


class LoginStep1Form(forms.Form):
    """Step 1 login form — username and password."""

    username = forms.CharField(label="Логін")
    password = forms.CharField(widget=forms.PasswordInput, label="Пароль")


class SignForm(forms.Form):
    """Form for signing ECP challenge with private key.

    Args:
        username: User login name.
        password: Password used to decrypt private key.
        private_key_file: Encrypted PEM private key file.

    Example:
        form = SignForm(request.POST, request.FILES)
        if form.is_valid():
            private_key_file = form.cleaned_data["private_key_file"]
    """

    username = forms.CharField(label="Логін")
    password = forms.CharField(
        widget=forms.PasswordInput,
        label="Пароль від ключа",
    )
    private_key_file = forms.FileField(
        label="Файл приватного ключа (.pem)",
        help_text="Завантажте private_key.pem отриманий при реєстрації.",
    )
