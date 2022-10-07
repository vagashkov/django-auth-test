# django-auth-test
Simple Django auth system usage example:
- user registration (with email and password only);
- user login (by username and password).

Test for most common registration and login errors:
- open registration page;
- register user with good credentials;
- register user with too short password;
- register user with different password and confirmation;
- register user with invalid email;
- register already registered user;
- open login page;
- login user with good credentials;
- login user with empty password;
- login user with empty username;
- login user with bad password or username.