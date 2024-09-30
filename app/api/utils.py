from django.contrib.auth import get_user_model




def get_account_type(user):
    return user.role  # Ensure this is accessed from the correct user mode

