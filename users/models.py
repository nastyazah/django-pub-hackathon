"""Custom user model with ECP public key field."""

from __future__ import annotations

from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """Extended user model with ECP public key storage.

    Extends AbstractUser — inherits all standard Django fields.
    Adds public_key for ECP signature verification at login.
    Private key is NEVER stored — only returned to user at registration.

    Example:
        user = User.objects.get(username='john')
        print(user.public_key)
    """

    public_key = models.TextField(
        blank=True,
        default='',
        verbose_name='ECP public key',
        help_text='PEM-encoded EC public key. Private key is never stored.',
    )
