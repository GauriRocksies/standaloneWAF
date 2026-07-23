"""
Django settings for VulneraBlog project.
"""

import os
from pathlib import Path
from decouple import config

# Build paths
BASE_DIR = Path(__file__).resolve().parent.parent

# Security
SECRET_KEY = config('SECRET_KEY', default='isecure_key')
DEBUG = config('DEBUG', default=True, cast=bool)
ALLOWED_HOSTS = ['*']

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'blog',
    'waf',
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

ROOT_URLCONF = 'vulnerablog.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.media',
            ],
        },
    },
]

WSGI_APPLICATION = 'vulnerablog.wsgi.application'

# PostgreSQL Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config("DB_NAME"),
        'USER': config("DB_USER"),
        'PASSWORD': config("DB_PASSWORD"),
        'HOST': config("DB_HOST", default="localhost"),
        'PORT': config("DB_PORT", default="5432"),
    }
}

# Custom User Model
AUTH_USER_MODEL = 'blog.User'

# Custom Authentication Backend (login via user_id_code)
AUTHENTICATION_BACKENDS = [
    'blog.auth_backends.UsernameBackend',
    'django.contrib.auth.backends.ModelBackend',
]

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Authentication redirects
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/login/'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Message tags
from django.contrib.messages import constants as messages
MESSAGE_TAGS = {
    messages.DEBUG: 'debug',
    messages.INFO: 'info',
    messages.SUCCESS: 'success',
    messages.WARNING: 'warning',
    messages.ERROR: 'error',
}

#email
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
# =========================================================
# WAF Logging Configuration (Member 3 module)
# =========================================================
# Physical log files live outside the DB (attacks.log / waf.log /
# access.log) so raw request data is still recoverable even if the
# database write in attack_logger.py fails or the DB is unavailable.

LOGS_DIR = BASE_DIR / 'logs'
os.makedirs(LOGS_DIR, exist_ok=True)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,

    'formatters': {
        'waf_verbose': {
            # General WAF component logs (errors, warnings, debug info)
            'format': '[{asctime}] {levelname} {name}: {message}',
            'style': '{',
        },
        'attack_line': {
            # One line per detected attack, kept parseable/grep-friendly
            'format': '[{asctime}] {message}',
            'style': '{',
        },
    },

    'handlers': {
        'waf_file': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': LOGS_DIR / 'waf.log',
            'maxBytes': 5 * 1024 * 1024,  # 5 MB
            'backupCount': 5,
            'formatter': 'waf_verbose',
        },
        'attack_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': LOGS_DIR / 'attacks.log',
            'maxBytes': 5 * 1024 * 1024,
            'backupCount': 5,
            'formatter': 'attack_line',
        },
        'access_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': LOGS_DIR / 'access.log',
            'maxBytes': 5 * 1024 * 1024,
            'backupCount': 5,
            'formatter': 'waf_verbose',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'waf_verbose',
        },
    },

    'loggers': {
        # General WAF component logging: waf.logging.logger.get_logger(__name__)
        'waf': {
            'handlers': ['waf_file', 'console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        # Dedicated attack channel: waf.logging.attack_logger.log_attack(...)
        'waf.attacks': {
            'handlers': ['attack_file'],
            'level': 'INFO',
            'propagate': False,
        },
        # Every incoming request, written by middleware (teammate's module)
        'waf.access': {
            'handlers': ['access_file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}