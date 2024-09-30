from rest_framework import serializers

class OTPVerificationSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6)