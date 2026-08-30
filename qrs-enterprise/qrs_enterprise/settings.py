"""
Django settings for the QRS Enterprise project.

Local-only by default: the server is intended to be exposed on a private
network (127.0.0.1 / LAN), never to the public internet. All secrets are
injected via environment variables.
"""
import os
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Environment-driven configuration
# ---------------------------------------------------------------------------
SECRET_KEY = os.environ.get("QRS_ENTERPRISE_SECRET_KEY", "dev-insecure-secret-key-change-me")

DEBUG = os.environ.get("QRS_ENTERPRISE_DEBUG", "1") == "1"

# Local-only: restrict to loopback / private hosts by default.
ALLOWED_HOSTS = [
    h.strip()
    for h in os.environ.get(
        "QRS_ENTERPRISE_ALLOWED_HOSTS", "127.0.0.1,localhost,::1"
    ).split(",")
    if h.strip()
]

# Data directory (sqlite + media + static) so it survives container rebuilds.
DATA_DIR = Path(os.environ.get("QRS_ENTERPRISE_DATA_DIR", str(BASE_DIR)))

# Dedicated key-encryption key for the Fernet KeyVault. MUST be set in
# production. Generate with: python manage.py qrs_enterprise_generate_key_enc_key
KEY_ENC_KEY = os.environ.get("QRS_ENTERPRISE_KEY_ENC_KEY", "")


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework.authtoken',
    'corsheaders',
    'enterprise',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'qrs_enterprise.urls'

AUTH_USER_MODEL = 'enterprise.User'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'qrs_enterprise.wsgi.application'


# Database
# https://docs.djangoproject.com/en/6.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': DATA_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/6.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/6.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/6.1/howto/static-files/

STATIC_URL = 'static/'
STATIC_ROOT = DATA_DIR / 'static'
MEDIA_URL = 'media/'
MEDIA_ROOT = DATA_DIR / 'media'

STORAGES = {
    'default': {'BACKEND': 'django.core.files.storage.FileSystemStorage'},
    'staticfiles': {'BACKEND': 'whitenoise.storage.CompressedStaticFilesStorage'},
}

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ---------------------------------------------------------------------------
# DRF
# ---------------------------------------------------------------------------
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        # TokenAuthentication first so the SPA's token-authenticated requests
        # are not subject to SessionAuthentication's CSRF enforcement (which
        # would fail when a Django-admin session cookie is also present).
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
        'enterprise.authentication.ApiKeyAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '60/min',
        'user': '120/min',
    },
}

# ---------------------------------------------------------------------------
# CORS (local-only; the SPA is served by the same origin, so this is permissive
# but restricted to private hosts by default).
# ---------------------------------------------------------------------------
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        'QRS_ENTERPRISE_CORS_ORIGINS', 'http://127.0.0.1:8000,http://localhost:8000'
    ).split(',')
    if o.strip()
]

# ---------------------------------------------------------------------------
# Upload limits (attachments can be large)
# ---------------------------------------------------------------------------
DATA_UPLOAD_MAX_MEMORY_SIZE = 100 * 1024 * 1024  # 100 MB
DATA_UPLOAD_MAX_NUMBER_FIELDS = 10_000

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {'format': '{levelname} {asctime} {name} {message}', 'style': '{'},
    },
    'handlers': {
        'console': {'class': 'logging.StreamHandler', 'formatter': 'verbose'},
    },
    'root': {
        'handlers': ['console'],
        'level': os.environ.get('QRS_ENTERPRISE_LOG_LEVEL', 'INFO'),
    },
    'loggers': {
        'enterprise': {'handlers': ['console'], 'level': 'INFO', 'propagate': False},
    },
}
