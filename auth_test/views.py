import logging

from datetime import datetime

from django.shortcuts import render, redirect
from django.views.generic.base import View
from django.contrib import messages
from validate_email import validate_email
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.utils.decorators import classonlymethod

from .forms import RegistrationForm


class RegistrationView(View):
    '''
    Manages new user registration process.
    '''

    def dispatch(self, request, *args, **kwargs):
        # Try to dispatch to the right method; if a method doesn't exist,
        # defer to the error handler. Also defer to the error handler if the
        # request method isn't on the approved list.
        logger = logging.getLogger(__name__)
        now = datetime.now()
        logger.info(now.strftime("%d/%m/%Y %H:%M:%S") + " " + logger.name + " Got " + request.method + " request for " + request.path)

        if request.method.lower() in self.http_method_names:
            handler = getattr(
                self, request.method.lower(), self.http_method_not_allowed
            )
        else:
            handler = self.http_method_not_allowed
        return handler(request, *args, **kwargs)

    def get(self, request):
        form = RegistrationForm()
        return render(request, 'auth/register.html', {'form': form})

    @method_decorator(csrf_protect)
    @method_decorator(sensitive_post_parameters())
    def post(self, request):
        logger = logging.getLogger(__name__)
        now = datetime.now()

        # Getting form data from request
        form = RegistrationForm(request.POST)
        has_error = False
        # Checking if form is valid
        if form.is_valid():
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password1 = form.cleaned_data['password1']
            password2 = form.cleaned_data['password2']

            # First, check user email format
            if not validate_email(email):
                has_error = True

            # Second, check password length
            if len(password1) < 6:
                has_error = True

            # Third, compare password and its confirmation
            if password1 != password2:
                has_error = True

            # Easy job done - now let's check user email for double registration
            try:
                if User.objects.get(email=email):
                    logger.error(now.strftime(
                        "%d/%m/%Y %H:%M:%S") + " " + logger.name + ":  User double registration")
                    has_error = True
            except User.DoesNotExist:
                pass

            # If data is not valid - reopen registration form
            if has_error:
                # If form data is not valid - log this event and return ser back to registration page
                logger.error(now.strftime(
                    "%d/%m/%Y %H:%M:%S") + " " + logger.name + ":  User registration form data is not valid: " + str(
                    form.errors))
                return render(request, 'auth/register.html', {'form': form})

            # All checks are passed - let's create new user!
            user = User.objects.create_user(username=username, email=email)
            user.set_password(password1)
            user.first_name = ''
            user.last_name = ''
            user.is_active = True
            user.save()
            return redirect('login')
        # If form data is not valid - log this event and return ser back to registration page
        logger.error(now.strftime("%d/%m/%Y %H:%M:%S") + " " + logger.name + ":  User registration form data is not valid: " + str(form.errors))
        return render(request, 'auth/register.html', {'form': form})


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
        password = request.POST.get('password1')

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




