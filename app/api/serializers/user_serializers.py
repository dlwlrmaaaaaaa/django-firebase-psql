from rest_framework import serializers
from django.contrib.auth import get_user_model

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import Token
from rest_framework_simplejwt.views import TokenObtainPairView
from ..utils import get_account_type
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password

User = get_user_model()

class CitizenSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    password = serializers.CharField(
        write_only=True, 
        required=True, 
        validators=[validate_password], 
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        write_only=True, 
        required=True, 
        style={'input_type': 'password'}
    )
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password_confirm', 'contact_number', 'address']
    
        def validate(self, attrs):
            if attrs['password'] != attrs['password_confirm']:
                raise serializers.ValidationError({'password': 'Password fields did not match.'})
            return attrs
    
    def create(self, validated_data):
        user = User(
            username=validated_data['username'],
            email=validated_data['email'],
            role='citizen', 
            contact_number=validated_data.get('contact_number'),
            address=validated_data.get('address'),
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

class DepartmentAdminSerializer(serializers.ModelSerializer):

    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    password = serializers.CharField(
        write_only=True, 
        required=True, 
        validators=[validate_password], 
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        write_only=True, 
        required=True, 
        style={'input_type': 'password'}
    )
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password_confirm', 'department', 'contact_number']

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({"password": "Password fields did not match." })
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')

        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            department=validated_data.get('department'),
            contact_number=validated_data.get('contact_number'),
            role='department_admin'
        )
        user.set_password(validated_data['password'])
        user.save()

        return user
    
class WorkerSerializers(serializers.ModelSerializer):

    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    password = serializers.CharField(
        write_only=True, 
        required=True, 
        validators=[validate_password], 
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        write_only=True, 
        required=True, 
        style={'input_type': 'password'}
    )
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password_confirm', 'department', 'contact_number']

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({"password": "Password fields did not match." })
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        supervisor = self.context['request'].user

        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            department=validated_data.get('department'),
            supervisor=supervisor,
            contact_number=validated_data.get('contact_number'),
            role='department_admin'
        )
        user.set_password(validated_data['password'])
        user.save()

        return user






class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)

        # Get the user account type
        account_type = get_account_type(self.user)

        # Add the account type to the token response
        data['account_type'] = account_type

        return data