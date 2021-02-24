import logging

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation

from djangae.contrib.googleauth import (
    _GOOG_JWT_ASSERTION_HEADER,
    _GOOG_AUTHENTICATED_USER_EMAIL_HEADER,
    _GOOG_AUTHENTICATED_USER_ID_HEADER,
    _IAP_AUDIENCE
)
from djangae.contrib.googleauth.models import UserManager

from google.auth.transport import requests
from google.oauth2 import id_token
from . import _find_atomic_decorator, _generate_unused_username
from .base import BaseBackend

User = get_user_model()


class IAPBackend(BaseBackend):

    @classmethod
    def can_authenticate(cls, request):
        return _GOOG_AUTHENTICATED_USER_EMAIL_HEADER in request.META and \
            _GOOG_AUTHENTICATED_USER_EMAIL_HEADER in request.META and \
            _GOOG_JWT_ASSERTION_HEADER in request.META

    def authenticate(self, request, **kwargs):
        error_partial = 'An attacker might have tried to bypass IAP.'
        atomic = _find_atomic_decorator(User)
        user_id = request.META.get(_GOOG_AUTHENTICATED_USER_ID_HEADER)
        email = request.META.get(_GOOG_AUTHENTICATED_USER_EMAIL_HEADER)

        # User not logged in to IAP
        if not user_id or not email:
            return

        # All IDs provided should be namespaced
        if ":" not in user_id or ":" not in email:
            return

        # Google tokens are namespaced with "auth.google.com:"
        namespace, user_id = user_id.split(":", 1)
        _, email = email.split(":", 1)

        if not getattr(request, "_through_local_iap_middleware", False):
            try:
                audience = _get_IAP_audience_from_settings()
            except AttributeError:
                raise ImproperlyConfigured(
                    "You must specify a %s in settings when using IAPBackend" % (
                        _IAP_AUDIENCE,
                    ))
            iap_jwt = request.META.get(_GOOG_JWT_ASSERTION_HEADER)

            try:
                signed_user_id, signed_user_email = _validate_iap_jwt(iap_jwt, audience)
            except ValueError as e:
                raise SuspiciousOperation("**ERROR: JWT validation error {}**\n{}".format(e, error_partial))

            assert (signed_user_id == user_id), (
                    f"IAP signed user id does not match {_GOOG_AUTHENTICATED_USER_ID_HEADER}. ",
                    error_partial,
                )
            assert (signed_user_email == email), (
                    f"IAP signed user email does not match {_GOOG_AUTHENTICATED_USER_EMAIL_HEADER}. ",
                    error_partial,
                )

        email = UserManager.normalize_email(email)
        assert email

        username = email.split("@", 1)[0]

        with atomic():
            # Look for a user, either by ID, or email
            user = User.objects.filter(google_iap_id=user_id).first()
            if not user:
                # We explicitly don't do an OR query here, because we only want
                # to search by email if the user doesn't exist by ID. ID takes
                # precendence.
                user = User.objects.filter(email_lower=email.lower()).first()

                if user and user.google_iap_id:
                    logging.warning(
                        "Found an existing user by email (%s) who had a different "
                        "IAP user ID (%s != %s). This seems like a bug.",
                        email, user.google_iap_id, user_id
                    )

                    # We don't use this to avoid accidentally "stealing" another
                    # user
                    user = None

            if user:
                # So we previously had a user sign in by email, but not
                # via IAP, so we should set that ID
                if not user.google_iap_id:
                    user.google_iap_id = user_id
                    user.google_iap_namespace = namespace
                else:
                    # Should be caught above if this isn't the case
                    assert(user.google_iap_id == user_id)

                # Update the email as it might have changed or perhaps
                # this user was added through some other means and the
                # sensitivity of the email differs etc.
                user.email = email

                # Note we don't update the username, as that may have
                # been overridden by something post-creation
                user.save()
            else:
                with atomic():
                    # First time we've seen this user
                    user = User.objects.create(
                        google_iap_id=user_id,
                        google_iap_namespace=namespace,
                        email=email,
                        username=_generate_unused_username(username)
                    )
                    user.set_unusable_password()
                    user.save()

        return user


def _validate_iap_jwt(iap_jwt, expected_audience):
    """Validate an IAP JWT.

    Args:
      iap_jwt: The contents of the X-Goog-IAP-JWT-Assertion header.
      expected_audience: The Signed Header JWT audience. See
          https://cloud.google.com/iap/docs/signed-headers-howto
          for details on how to get this value.

    Returns:
      (user_id, user_email).
    """

    decoded_jwt = id_token.verify_token(
        iap_jwt, requests.Request(), audience=expected_audience,
        certs_url='https://www.gstatic.com/iap/verify/public_key')
    return (decoded_jwt['sub'], decoded_jwt['email'])


def _get_IAP_audience_from_settings():
    return getattr(settings, _IAP_AUDIENCE)
