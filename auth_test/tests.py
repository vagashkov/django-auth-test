from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User


class BaseTest(TestCase):
    '''
    Manages base test case setup process,
    setting test users credentials
    '''
    def setUp(self):
        # setting up registration and login paths
        self.register_url = reverse('register')
        self.login_url = reverse('login')
        self.logout_url = reverse('logout')

        # good user test info
        self.good_user = {
            'email': 'good_user@test.com',
            'username': 'good_user',
            'password1': 'password',
            'password2': 'password',
        }

        # user with too short password
        self.user_short_password = {
            'email': 'short_pwd@test.com',
            'username': 'short_pwd',
            'password1': 'short',
            'password2': 'short',
        }

        # user with different password and confirmation
        self.user_different_passwords = {
            'email': 'diff_pwds@test.com',
            'username': 'diff_pwds',
            'password1': 'different',
            'password2': 'passwords',
        }

        # user with invalid email
        self.user_invalid_email = {
            'email': 'test.com',
            'username': 'inv_email',
            'password1': 'invalidemail',
            'password2': 'invalidemail',
        }
        return super().setUp()


class RegistrationTest(BaseTest):
    '''
    Manages registration functionality test process.
    '''
    def test_open_registration_page(self):
        # Getting registration test by reverse url
        response = self.client.get(self.register_url)
        # Checking if page generated successfully
        self.assertEqual(response.status_code, 200)
        # Checking if page generated using correct template
        self.assertTemplateUsed(response, 'auth/register.html')


    def test_register_good_user(self):
        # Try to register user with valid credentials
        response = self.client.post(self.register_url, self.good_user, format='text/html')
        # Check if user was really registered
        users = get_user_model().objects.all()
        self.assertEqual(str(users[0]), 'good_user')


    def test_register_short_password_user(self):
        # Try to register user with too short password
        response = self.client.post(self.register_url, self.user_short_password, format='text/html')
        # Check result (has to be unauthorized)
        self.assertEqual(response.status_code, 401)

    def test_register_different_passwords_user(self):
        # Try to register user with different password and confirmation
        response = self.client.post(self.register_url, self.user_different_passwords, format='text/html')
        # Check result (has to be unauthorized)
        self.assertEqual(response.status_code, 401)

    def test_register_invalid_email_user(self):
        # Try to register user with invalid email
        response = self.client.post(self.register_url, self.user_invalid_email, format='text/html')
        # Check result (has to be unauthorized)
        self.assertEqual(response.status_code, 401)

    def test_register_double_user(self):
        # Register good user
        self.client.post(self.register_url, self.good_user, format='text/html')
        # And try to register him one more time
        response = self.client.post(self.register_url, self.good_user, format='text/html')
        # Check result (has to be unauthorized)
        self.assertEqual(response.status_code, 401)


class LoginTest(BaseTest):
    '''
    Manages login functionality test process.
    '''
    def test_open_login_page(self):
        # Getting login page by reverse url
        response = self.client.get(self.login_url)
        # Checking if page generated successfully
        self.assertEqual(response.status_code, 200)
        # Checking if page generated using correct template
        self.assertTemplateUsed(response, 'auth/login.html')

    def test_successful_login(self):
        # Register user with proper credentials
        self.client.post(self.register_url, self.good_user, format='text/html')
        # Try to login with the same credentials
        response = self.client.post(self.login_url, self.good_user, format='text/html')
        # Check for redirection after successful login (to home page)
        self.assertEqual(response.status_code, 302)

    def test_failed_login_with_empty_username(self):
        # Try to login user with empty username
        response = self.client.post(self.login_url, {'username': '', 'password': 'goodpassword'}, format='text/html')
        # Check result (has to be unauthorized)
        self.assertEqual(response.status_code, 401)

    def test_failed_login_with_no_password(self):
        # Try to login user with empty password
        response = self.client.post(self.login_url, {'username': 'goodusername', 'password': ''}, format='text/html')
        # Check result (has to be unauthorized)
        self.assertEqual(response.status_code, 401)

    def test_failed_login_with_wrong_username_and_password(self):
        # Try to login user with wrong username and password
        response = self.client.post(self.login_url, {'username': 'username', 'password': 'password'}, format='text/html')
        # Check result (has to be unauthorized)
        self.assertEqual(response.status_code, 401)


class LogoutTest(BaseTest):
    '''
    Manages logou functionality test process.
    '''
    def test_logout_action(self):
        # Register user with proper credentials
        self.client.post(self.register_url, self.good_user, format='text/html')
        # Login user with the same credentials
        response = self.client.post(self.login_url, self.good_user, format='text/html')
        # Check for redirection after successful login (to home page)
        self.assertEqual(response.status_code, 302)
        # Try to logout using reverse url
        response = self.client.post(self.logout_url)
        # Checking if page generated successfully
        self.assertEqual(response.status_code, 302)
        # Check if after logout user will be redirected to login page
        self.assertEqual(response.url, "/login")
