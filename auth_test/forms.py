from django import forms


class RegistrationForm(forms.Form):
    email = forms.EmailField(widget=forms.EmailInput(attrs={'placeholder': 'Email'}), required=True)
    username = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'Username'}), required=True)
    password1 = forms.CharField(widget=forms.PasswordInput(), required=True)
    password2 = forms.CharField(widget=forms.PasswordInput(), required=True)
    is_agreed = forms.BooleanField(widget=forms.CheckboxInput(), required=True)

