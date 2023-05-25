import re
from django.core.exceptions import ValidationError
from allauth.account.adapter import DefaultAccountAdapter


class MyAccountAdapter(DefaultAccountAdapter):

    def clean_password(self, password, user=None):
        # Insert your rules here
        min_length = 10
        try:
            validate_password(password, user)
        except:
            if min_length and len(password) < min_length:
                raise ValidationError(
                    ("The password must be a minimum of 10 characters.").format(min_length)
                )

            if not re.findall('\d', password):
                raise ValidationError(
                    ("The password must contain at least 1 digit, 0-9."),
                    code='password_no_number',
                )

            if not re.findall('[A-Z]', password):
                raise ValidationError(
                    ("The password must contain at least 1 uppercase letter, A-Z."),
                    code='password_no_upper',
                )

            if not re.findall('[a-z]', password):
                raise ValidationError(
                    ("The password must contain at least 1 lowercase letter, a-z."),
                    code='password_no_lower',
                )

            if not re.findall('[()[\]{}|\\`~!@#$%^&*_\-+=;:\'",<>./?]', password):
                raise ValidationError(
                    ("The password must contain at least 1 symbol: " +
                    "()[]{}|\`~!@#$%^&*_-+=;:'\",<>./?"),
                    code='password_no_symbol',
                )
        return password