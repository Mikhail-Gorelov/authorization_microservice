from django.conf import settings
from django.contrib.auth import get_user_model, password_validation
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django import forms
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import ValidationError
from rest_framework.reverse import reverse_lazy

from api.v1.auth_app.services import AuthAppService
from src.celery import app

User = get_user_model()

class SetPasswordForm(forms.Form):
    """
    A form that lets a user change set their password without entering the old
    password
    """
    error_messages = {
        'password_mismatch': _('The two password fields didn’t match.'),
    }
    new_password1 = forms.CharField(
        label=_("New password"),
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        strip=False,
        help_text=password_validation.password_validators_help_text_html(),
    )
    new_password2 = forms.CharField(
        label=_("New password confirmation"),
        strip=False,
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_new_password2(self):
        password1 = self.cleaned_data.get('new_password1')
        password2 = self.cleaned_data.get('new_password2')
        if password1 and password2:
            if password1 != password2:
                raise ValidationError(
                    self.error_messages['password_mismatch'],
                    code='password_mismatch',
                )
        password_validation.validate_password(password2, self.user)
        return password2

    def save(self, commit=True):
        password = self.cleaned_data["new_password1"]
        self.user.set_password(password)
        if commit:
            self.user.save()
        return self.user


class PassResetForm(PasswordResetForm):
    def get_reset_url(self, uid, token):
        path = "auth_app:password-reset-confirm"
        url = reverse_lazy(path, kwargs={'uidb64': uid, 'token': token})
        return settings.FRONTEND_SITE + str(url)

    def save(
        self,
        domain_override=None,
        subject_template_name='account/email/password_reset_subject.txt',
        email_template_name='account/email/password_reset_email.html',
        use_https=False,
        token_generator=default_token_generator,
        from_email=None,
        request=None,
        html_email_template_name='account/email/password_reset_email.html',
        extra_email_context=None,
        **kwargs
    ):
        """
        Generate a one-use only link for resetting password and send it to the user.
        """
        email = self.cleaned_data["email"]
        user = AuthAppService.get_user(email=email)
        if not user:
            raise ValidationError({'email': _('User does not exist with this email')})
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = token_generator.make_token(user)
        url = self.get_reset_url(uid=uid, token=token)

        data = {
            'subject': 'Your reset e-mail',
            'template_name': "auth_app/reset_password_sent.html",
            'to_email': email,
            'context': {
                'user': user.get_full_name(),
                'reset_url': url,
            },
        }
        app.send_task(
            name='email_sender.tasks.send_information_email',
            kwargs=data,
        )
