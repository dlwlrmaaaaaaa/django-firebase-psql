from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth import get_user_model
User = get_user_model()
class OTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField(
        required=True,
    )
    otp = serializers.CharField(max_length=6)