"""Django settings for backend project."""

import os
from pathlib import Path
from urllib.parse import unquote, urlparse

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get(
    'DJANGO_SECRET_KEY',
    'django-insecure-4cd8phcl_g)j$0wy!@zl5!sv*f$3ddv*7@jke(#p!uhw88%$s&',
)

DEBUG = os.environ.get('DEBUG', 'False').lower() in {'1', 'true', 'yes', 'on'}

ALLOWED_HOSTS = [host.strip() for host in os.environ.get('ALLOWED_HOSTS', '').split(',') if host.strip()]

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django_ecp_auth',
    'users',
]

AUTH_USER_MODEL = 'users.User'

AUTHENTICATION_BACKENDS = [
    'django_ecp_auth.backends.ecp_backend.EcpAuthBackend',
    'django.contrib.auth.backends.ModelBackend',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.jinja2.Jinja2',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'environment': 'backend.jinja2.environment',
            'context_processors': [
                'django.template.context_processors.request',
                'django.template.context_processors.csrf',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.template.context_processors.csrf',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'backend.wsgi.application'

DATABASE_URL = os.environ.get('DATABASE_URL', '')

if DATABASE_URL:
    parsed_db = urlparse(DATABASE_URL)
    db_engines = {
        'postgres': 'django.db.backends.postgresql',
        'postgresql': 'django.db.backends.postgresql',
        'sqlite': 'django.db.backends.sqlite3',
    }
    db_engine = db_engines.get(parsed_db.scheme)
    if not db_engine:
        raise ValueError(f'Unsupported DATABASE_URL scheme: {parsed_db.scheme}')
    if db_engine == 'django.db.backends.sqlite3':
        DATABASES = {'default': {'ENGINE': db_engine, 'NAME': parsed_db.path.lstrip('/') or str(BASE_DIR / 'db.sqlite3')}}
    else:
        DATABASES = {'default': {'ENGINE': db_engine, 'NAME': parsed_db.path.lstrip('/'),
            'USER': unquote(parsed_db.username or ''), 'PASSWORD': unquote(parsed_db.password or ''),
            'HOST': parsed_db.hostname or '', 'PORT': str(parsed_db.port or '')}}
else:
    DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': BASE_DIR / 'db.sqlite3'}}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
STATICFILES_DIRS = [BASE_DIR / 'static']

LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'dashboard'
LOGOUT_REDIRECT_URL = 'login'

ECP_AUTH = {
    'TRUSTED_CA_CERTS': os.environ.get('ECP_TRUSTED_CA_CERTS', ''),
    'CERT_VALIDATION_ENABLED': os.environ.get('ECP_CERT_VALIDATION', 'False') == 'True',
    'USER_MODEL_FIELD': 'username',
    'AUTO_CREATE_USER': False,
    'LOGIN_TEMPLATE': 'auth/ecp_login.html',
    'LOGIN_REDIRECT_URL': 'dashboard',
    'LOGOUT_REDIRECT_URL': 'login',
    'REQUIRE_STEP1_SESSION': True,
}
