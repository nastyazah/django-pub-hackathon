"""Add public_key field to User model."""

from django.db import migrations, models


class Migration(migrations.Migration):
    """Migration to add ECP public_key field to users.User."""

    dependencies = [
        ('users', '0002_alter_user_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='public_key',
            field=models.TextField(
                blank=True,
                default='',
                help_text='PEM-encoded EC public key. Private key is never stored.',
                verbose_name='ECP public key',
            ),
        ),
    ]
