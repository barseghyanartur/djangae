from django.http.response import HttpResponse
from django.test.utils import override_settings
from djangae.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import path

from unittest.mock import patch

User = get_user_model()

urlpatterns = [
    path('', lambda request: HttpResponse('Ok'), name='index')
]


@override_settings(ROOT_URLCONF=__name__, GOOGLEAUTH_IAP_JWT_AUDIENCE="something")
class IAPAuthenticationTests(TestCase):
    @patch('djangae.contrib.googleauth.backends.iap.id_token.verify_token')
    def test_user_created_if_authenticated(self, verify_token_mock):
        user = 99999
        user_email = 'test@example.com'
        verify_token_mock.return_value = (user, user_email, '')

        headers = {
            'HTTP_X_GOOG_AUTHENTICATED_USER_ID': f'auth.example.com:{user}',
            'HTTP_X_GOOG_AUTHENTICATED_USER_EMAIL': f'auth.example.com:̦{user_email}',
            'X-GOOG-IAP-JWT-ASSERTION': 'JWT',
        }

        self.client.get("/", **headers)

        self.assertTrue(User.objects.exists())

        user = User.objects.get()

        self.assertEqual(user.google_iap_id, '99999')
        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.username, 'test')
        self.assertFalse(user.has_usable_password())

    def test_email_change(self):
        headers = {
            'HTTP_X_GOOG_AUTHENTICATED_USER_ID': 'auth.example.com:99999',
            'HTTP_X_GOOG_AUTHENTICATED_USER_EMAIL': 'auth.example.com:test@example.com',
            'X-GOOG-IAP-JWT-ASSERTION': 'JWT',
        }

        self.client.get("/", **headers)

        self.assertTrue(User.objects.exists())

        user = User.objects.get()

        self.assertEqual(user.google_iap_id, '99999')
        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.username, 'test')

        headers = {
            'HTTP_X_GOOG_AUTHENTICATED_USER_ID': 'auth.example.com:99999',
            'HTTP_X_GOOG_AUTHENTICATED_USER_EMAIL': 'auth.example.com:test22@example.com',
            'X-GOOG-IAP-JWT-ASSERTION': 'JWT',
        }

        self.client.get("/", **headers)

        user = User.objects.get()

        self.assertEqual(user.google_iap_id, '99999')
        self.assertEqual(user.email, 'test22@example.com')

        # Username not updated
        self.assertEqual(user.username, 'test')

    def test_email_case_insensitive(self):
        """
            Even though the RFC says that the part of an email
            address before the '@' is case sensitive, basically no
            mail provider does that, and to allow differences in case
            causes more issues than it solves, so we ensure that although
            we retain the original case of an email, you can't create different
            users with emails that differ in case alone.
        """

        user = User.objects.create(
            email='test22@example.com'
        )

        self.assertEqual(user.email, 'test22@example.com')

        headers = {
            'HTTP_X_GOOG_AUTHENTICATED_USER_ID': 'auth.example.com:99999',
            'HTTP_X_GOOG_AUTHENTICATED_USER_EMAIL': 'auth.example.com:tESt22@example.com',
            'X-GOOG-IAP-JWT-ASSERTION': 'JWT',
        }

        self.client.get("/", **headers)

        user = User.objects.get()

        self.assertEqual(user.email, 'tESt22@example.com')
