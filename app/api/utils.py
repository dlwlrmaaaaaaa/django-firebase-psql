from django.contrib.auth import get_user_model
from firebase_admin import auth

def generate_firebase_token(user):
    additional_claims = {
        "role": user.role,  
    }
    return auth.create_custom_token(str(user.id), additional_claims)

def get_account_type(user):
    return user.role  # Ensure this is accessed from the correct user mode

