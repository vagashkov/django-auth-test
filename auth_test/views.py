from django.shortcuts import render, redirect
from django.views.generic import View
from django.contrib import messages
from validate_email import validate_email
from django.contrib.auth.models import User


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
            return render(request, 'auth/register.html', context)

        # All checks are passed - let's create new user!
        username = request.POST.get("username")
        user = User.objects.create_user(username=username, email=email)
        user.set_password(password)
        user.first_name = ''
        user.last_name = ''
        user.is_active = False
        user.save()

        # messages.add_message(request, messages.SUCCESS, 'account created successfully')
        return redirect('login')


class LoginView(View):
    '''
    Manages user authorization process.
    '''
    def get(self, request):
        return render(request, 'auth/login.html')

    #
    #   return render(request, 'auth/register.html', context=context)
    #
    #     current_site = get_current_site(request)
    #     email_subject = 'Active your Account'
    #     message = render_to_string('auth/activate.html',
    #                                {
    #                                    'user': user,
    #                                    'domain': current_site.domain,
    #                                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
    #                                    'token': generate_token.make_token(user)
    #                                }
    #                                )
    #
    #     email_message = EmailMessage(
    #         email_subject,
    #         message,
    #         settings.EMAIL_HOST_USER,
    #         [email]
    #     )
    #
    #     EmailThread(email_message).start()

    #
    #
