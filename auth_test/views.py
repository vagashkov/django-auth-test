from django.shortcuts import render, redirect
from django.views.generic import View
from django.contrib import messages
from validate_email import validate_email
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout


class RegistrationView(View):
    '''
    Manages new user registration process.
    '''
    def get(self, request):
        return render(request, 'auth/register.html')

    def post(self, request):
        context = {
            'data': request.POST,
            'has_error': False
        }

        # First, check user email format
        email = request.POST.get('email')
        if not validate_email(email):
            messages.add_message(request, messages.ERROR, 'Please provide a valid email')
            context['has_error'] = True

        # Second, check password length
        password = request.POST.get('password')
        if len(password) < 6:
            messages.add_message(request, messages.ERROR, 'password has to be at least 6 characters long')
            context['has_error'] = True

        # Third, compare password and its confirmation
        password2 = request.POST.get('password2')
        if password != password2:
            messages.add_message(request, messages.ERROR, 'passwords dont match')
            context['has_error'] = True

        # Easy job done - now let's check user email for double registration
        try:
            if User.objects.get(email=email):
                messages.add_message(request, messages.ERROR, 'Email already exists')
                context['has_error'] = True
        except User.DoesNotExist:
            pass

        # If data is not valid - reopen registration form
        if context['has_error']:
            return render(request, 'auth/register.html', status=401, context=context)

        # All checks are passed - let's create new user!
        username = request.POST.get("username")
        user = User.objects.create_user(username=username, email=email)
        user.set_password(password)
        user.first_name = ''
        user.last_name = ''
        user.is_active = True
        user.save()

        # messages.add_message(request, messages.SUCCESS, 'account created successfully')
        return redirect('login')


class LoginView(View):
    '''
    Manages user authorization process.
    '''
    def get(self, request):
        return render(request, 'auth/login.html')

    def post(self, request):
        context = {
            'data': request.POST,
            'has_error': False
        }

        # Getting user credentials
        username = request.POST.get('username')
        password = request.POST.get('password')

        # Check if user email is empty
        if not username:
            messages.add_message(request, messages.ERROR, 'Enter username')
            context['has_error'] = True

        # Check if password is empty
        if not password:
            messages.add_message(request, messages.ERROR, 'Enter password')
            context['has_error'] = True

        # If something is already wrong - no need to check credentials
        if context['has_error']:
            return render(request, 'auth/login.html', status=401, context=context)

        # Otherwise try to authenticate user with provided info
        user = authenticate(request, username=username, password=password)

        # User authentication error (not found or wrong password)
        if not user and not context['has_error']:
            messages.add_message(request, messages.ERROR, 'Invalid username and/or password')
            context['has_error'] = True
            return render(request, 'auth/login.html', status=401, context=context)

        # If we are here - everything went right
        # Login user and redirect him to home page
        login(request, user)
        return render(request, 'home.html', status=302, context=context)


class HomeView(View):
    '''
    Managers Home page realisation
    '''
    def get(self, request):
        return render(request, 'home.html')


class LogoutView(View):
    '''
    Manages user logiut process
    '''
    def post(self, request):
        logout(request)
        messages.add_message(request, messages.SUCCESS, 'Logout complete')
        return redirect('login')




