from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.contrib.auth import get_user_model
import json
import logging

from .models import AuthToken

logger = logging.getLogger(__name__)
User = get_user_model()

def login_view(request):
    """Render the login page"""
    # If already logged in, redirect to the chat page
    if request.user.is_authenticated:
        return redirect('chat')

    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        user = authenticate(request, email=email, password=password)

        if user is not None:
            login(request, user)
            # Generate auth token
            auth_token = AuthToken.generate_token(user)
            # Set token in session
            request.session['auth_token'] = auth_token.token
            # Log successful login
            logger.info(f"User {email} logged in successfully")

            # Explicitly set the session to modified to ensure it's saved
            request.session.modified = True

            return redirect('chat')
        else:
            logger.warning(f"Failed login attempt for {email}")
            return render(request, 'chatgpt_app/login.html', {
                'error': 'Invalid email or password'
            })

    return render(request, 'chatgpt_app/login.html')


def signup_view(request):
    """Render the signup page"""
    # If already logged in, redirect to the chat page
    if request.user.is_authenticated:
        return redirect('chat')

    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password_confirm = request.POST.get('password_confirm')

        # Check if passwords match
        if password != password_confirm:
            return render(request, 'chatgpt_app/signup.html', {
                'error': 'Passwords do not match'
            })

        # Check if email already exists
        if User.objects.filter(email=email).exists():
            return render(request, 'chatgpt_app/signup.html', {
                'error': 'Email already exists'
            })

        # Create user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password
        )

        # Log the user in
        login(request, user)

        # Generate auth token
        auth_token = AuthToken.generate_token(user)
        # Set token in session
        request.session['auth_token'] = auth_token.token

        # Explicitly set the session to modified to ensure it's saved
        request.session.modified = True

        logger.info(f"New user created: {email}")

        return redirect('chat')

    return render(request, 'chatgpt_app/signup.html')


def logout_view(request):
    """Log the user out"""
    # Get the user
    user = request.user

    # If the user is authenticated, log them out
    if user.is_authenticated:
        # Delete auth token if exists
        auth_token = request.session.get('auth_token')
        if auth_token:
            try:
                AuthToken.objects.filter(token=auth_token).delete()
            except:
                pass

        # Clear session
        request.session.flush()

        # Log out user
        logout(request)

        logger.info(f"User {user.email} logged out")

    return redirect('login')


@csrf_exempt
@require_POST
def api_login(request):
    """API endpoint for login"""
    try:
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return JsonResponse({'error': 'Email and password are required'}, status=400)

        user = authenticate(request, email=email, password=password)

        if user is not None:
            # Generate auth token
            auth_token = AuthToken.generate_token(user)

            # Log in the user
            login(request, user)

            # Set token in session
            request.session['auth_token'] = auth_token.token
            request.session.modified = True

            return JsonResponse({
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email
                },
                'token': auth_token.token,
                'expires_at': auth_token.expires_at.isoformat()
            })
        else:
            return JsonResponse({'error': 'Invalid email or password'}, status=401)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error in API login: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_POST
def api_signup(request):
    """API endpoint for signup"""
    try:
        data = json.loads(request.body)
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not username or not email or not password:
            return JsonResponse({'error': 'Username, email and password are required'}, status=400)

        # Check if email already exists
        if User.objects.filter(email=email).exists():
            return JsonResponse({'error': 'Email already exists'}, status=400)

        # Create user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password
        )

        # Log in the user
        login(request, user)

        # Generate auth token
        auth_token = AuthToken.generate_token(user)

        # Set token in session
        request.session['auth_token'] = auth_token.token
        request.session.modified = True

        return JsonResponse({
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            },
            'token': auth_token.token,
            'expires_at': auth_token.expires_at.isoformat()
        })

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error in API signup: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)
