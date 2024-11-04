from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from django.contrib.auth import get_user_model

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import Token
from rest_framework_simplejwt.views import TokenObtainPairView
from ..utils import get_account_type
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from rest_framework import status
import ipaddress
from django.conf import settings
from django.contrib.auth import authenticate

User = get_user_model()

class CitizenSerializer(serializers.ModelSerializer):

    username = serializers.CharField(
        required=True,
        allow_blank=False,
        validators=[UniqueValidator(queryset=User.objects.all(), message="This username is already taken.")]
    )
    email = serializers.EmailField(
        required=True,
        allow_blank=False,
         validators=[UniqueValidator(queryset=User.objects.all(), message="This email is already registered.")]
    )
    password = serializers.CharField(
        write_only=True, 
        required=True, 
        validators=[validate_password], 
        style={'input_type': 'password'},
        error_messages={'required': 'Password is required.'}
    )
    password_confirm = serializers.CharField(
        write_only=True, 
        required=True, 
        style={'input_type': 'password'},
        error_messages={'required': 'Password confirmation is required.'}
    )
    contact_number = serializers.CharField(
        required=True,
        allow_blank=False,
        validators=[UniqueValidator(queryset=User.objects.all(), message="This contact number is already in use.")]
    )
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password_confirm', 'contact_number', 'address', 'ipv']
        # fields = ['username', 'email', 'password', 'password_confirm', 'contact_number', 'address', 'ipv', 'profile_image_path']
    
    def validate(self, attrs):
        if 'password' in attrs and 'password_confirm' in attrs:
            if attrs['password'] != attrs['password_confirm']:
                raise serializers.ValidationError({'password': 'Password fields did not match.'})
            for field in ['username', 'email', 'contact_number']:
                if not attrs.get(field):  # Validate non-empty values
                    raise serializers.ValidationError({field: f"{field.capitalize()} cannot be empty."})
        return attrs
    def validate_ipv(self, value):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ValidationError("Invalid IP address format.")
        return value
    
    def create(self, validated_data):
        user = User(
            username=validated_data['username'],
            email=validated_data['email'],
            role='citizen', 
            contact_number=validated_data.get('contact_number'),
            address=validated_data.get('address'),
            ipv=validated_data.get('ipv')
        )
        user.set_password(validated_data['password'])
        user.save()
        return user
    
    def update(self, instance, validated_data):
        # If password is provided, update it
        password = validated_data.pop('password', None)
        password_confirm = validated_data.pop('password_confirm', None)

        if password and password_confirm:
            if password != password_confirm:
                raise serializers.ValidationError({"password": "Passwords must match."})
            instance.set_password(password)
        
        # Update the rest of the fields
        return super().update(instance, validated_data)

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
        fields = ['username', 'email', 'password', 'password_confirm', 'department', 'contact_number', 'ipv']

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
        username_or_email = attrs.get('username')  
        password = attrs.get('password') 
        user = authenticate(request=self.context.get('request'), username=username_or_email, password=password)

        if not user:
            raise ValidationError({"detail": "Invalid credentials. Please try again."}, code=status.HTTP_401_UNAUTHORIZED)

        if not user.is_active:
            raise ValidationError({"detail": "User account is disabled."}, code=status.HTTP_403_FORBIDDEN)

        self.user = user

        account_type = get_account_type(self.user)

        # if account_type == 'citizen':
        #     raise ValidationError({"detail": "Access restricted to admins only."}, code=status.HTTP_403_FORBIDDEN)
        
        data = super().validate(attrs)
        data['user_id'] = self.user.id
        data['username'] = self.user.username  
        data['user_id'] = self.user.id 
        data['email'] = self.user.email 
        data['address'] = self.user.address 
        data['contact_number'] = self.user.contact_number
        data['account_type'] = account_type 
        data['is_email_verified'] = self.user.is_email_verified 
        data['is_verified'] = self.user.is_verified 

        return data
    
class VerifyPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(required=True, write_only=True)

    def validate_password(self, value):
        # You can add additional validation if needed
        return value
    
class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(
        required=True, 
        write_only=True, 
        validators=[validate_password]
    )
    new_password_confirm = serializers.CharField(required=True, write_only=True)

    def validate(self, attrs):
        # Check if the new passwords match
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({"new_password": "New password fields did not match."})

        # Validate the current password
        user = self.context['request'].user
        if not user.check_password(attrs['current_password']):
            raise serializers.ValidationError({"current_password": "Current password is incorrect."})

        return attrs
    
class UsersSerializer(serializers.ModelSerializer):
    # username = serializers.SerializerMethodField()

    class Meta:
        model = User
        # fields = ['full_name', 'contact_number', 'is_email_verified', 'role', 'is_active', 'is_verified']
        fields = ['username', 'contact_number', 'is_verified', 'violation', 'role', 'account_status', 'address', 'email']

    # def get_full_name(self, obj):
    #     return f"{obj.first_name} {obj.last_name}"