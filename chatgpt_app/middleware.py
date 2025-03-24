import datetime
from django.shortcuts import redirect
from django.urls import reverse
from django.contrib.auth import get_user_model, login
from django.utils import timezone
import logging

from .models import AuthToken

logger = logging.getLogger(__name__)
User = get_user_model()

class AuthTokenMiddleware:
    """
    Middleware to authenticate users via token.

    This middleware checks for a token in the request headers or session,
    and authenticates the user if the token is valid.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip authentication for authentication-related views and static files
        if request.path.startswith('/static/') or request.path.startswith('/media/'):
            return self.get_response(request)

        # Skip authentication for authentication-related views
        if request.path in [reverse('login'), reverse('signup'),
                           '/api/login/', '/api/signup/']:
            return self.get_response(request)

        # Check if user is already authenticated
        if request.user.is_authenticated:
            # User is authenticated, continue with the request
            response = self.get_response(request)
            return response

        # Try to get token from session
        token_value = request.session.get('auth_token')

        # If not in session, try to get from authorization header
        if not token_value and 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Token '):
                token_value = auth_header.split(' ')[1]

        # If no token found, get from cookie
        if not token_value and 'auth_token' in request.COOKIES:
            token_value = request.COOKIES.get('auth_token')

        # If no token found, redirect to login
        if not token_value:
            # Prevent redirect loop by checking if we're already on login page
            if request.path == reverse('login'):
                return self.get_response(request)

            if request.path.startswith('/api/'):
                # If API request, return 401
                response = redirect(reverse('login'))
                response.status_code = 401
                return response
            else:
                # If browser request, redirect to login
                return redirect(reverse('login'))

        # Try to find token in database
        try:
            token = AuthToken.objects.get(token=token_value)

            # Check if token is expired
            if token.expires_at < timezone.now():
                # Delete expired token
                token.delete()

                # Clear session
                request.session.flush()

                # Prevent redirect loop by checking if we're already on login page
                if request.path == reverse('login'):
                    return self.get_response(request)

                return redirect(reverse('login'))

            # Token is valid, set user and login user
            request.user = token.user
            login(request, token.user)

            # Log successful authentication
            logger.debug(f"User {request.user.email} authenticated via token")

        except AuthToken.DoesNotExist:
            # Token not found, delete from session and cookies
            if 'auth_token' in request.session:
                del request.session['auth_token']

            # Prevent redirect loop by checking if we're already on login page
            if request.path == reverse('login'):
                return self.get_response(request)

            return redirect(reverse('login'))

        # Continue with the request
        response = self.get_response(request)
        return response
