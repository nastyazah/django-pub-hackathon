"""Forms for user registration and ECP authentication."""

from __future__ import annotations

from django import forms
from django.contrib.auth.password_validation import validate_password

from .models import User


class RegisterForm(forms.ModelForm):
    """Form for user registration with username and password.

    ECP keypair is generated in RegisterView after successful validation.

    Example:
        form = RegisterForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
    """

    password = forms.CharField(
        widget=forms.PasswordInput,
        label='Пароль',
    )
    password_confirm = forms.CharField(
        widget=forms.PasswordInput,
        label='Підтвердіть пароль',
    )

    class Meta:
        """Meta options for RegisterForm."""

        model = User
        fields = ['username']

    def clean(self) -> dict:
        """Validate that passwords match.

        Returns:
            Cleaned form data.

        Raises:
            ValidationError: If passwords do not match.
        """
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password_confirm = cleaned_data.get('password_confirm')
        if password and password_confirm and password != password_confirm:
            raise forms.ValidationError('Паролі не співпадають.')
        if password:
            validate_password(password)
        return cleaned_data


class LoginStep1Form(forms.Form):
    """Step 1 login form — username and password.

    Example:
        form = LoginStep1Form(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
    """

    username = forms.CharField(
        label='Логін',
    )
    password = forms.CharField(
        widget=forms.PasswordInput,
        label='Пароль',
    )
