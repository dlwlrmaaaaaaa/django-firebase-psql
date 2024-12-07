from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from django.contrib.auth import get_user_model

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import Token
from rest_framework_simplejwt.views import TokenObtainPairView
from ..utils import get_account_type
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from rest_framework import status
import ipaddress
from django.conf import settings
from django.contrib.auth import authenticate
from rest_framework import serializers
from ..models import Department

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
        fields = ['username', 'email', 'password', 'password_confirm', 'contact_number', 'address', 'coordinates', 'ipv', 'score']

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({'password_confirm': 'Passwords do not match.'})
        return attrs

    def validate_ipv(self, value):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise serializers.ValidationError("Invalid IP address format.")
        return value

    def create(self, validated_data):
        user = User(
            username=validated_data['username'],
            email=validated_data['email'],
            role='citizen',
            contact_number=validated_data.get('contact_number'),
            address=validated_data.get('address'),
            coordinates=validated_data.get('coordinates'),
            ipv=validated_data.get('ipv'),
            score=50
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        password_confirm = validated_data.pop('password_confirm', None)

        if password and password_confirm:
            if password != password_confirm:
                raise serializers.ValidationError({"password_confirm": "Passwords must match."})
            instance.set_password(password)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance


class DepartmentList(serializers.ModelSerializer):
    class Meta:
        model = Department
        fields = '__all__'
    
class DepartmentAdminSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all(), message="This email is already in use.")],
        error_messages={"required": "Email is required."}
    )
    password = serializers.CharField(
        write_only=True, 
        required=True, 
        validators=[validate_password], 
        style={'input_type': 'password'},
        error_messages={
            "required": "Password is required.",
            "blank": "Password cannot be empty."
        }
    )
    password_confirm = serializers.CharField(
        write_only=True, 
        required=True, 
        style={'input_type': 'password'},
        error_messages={
            "required": "Password confirmation is required.",
            "blank": "Password confirmation cannot be empty."
        }
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password_confirm', 'department', 'contact_number', 'station', 'station_address']

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({
                "password_confirm": "Passwords do not match."
            })
        return attrs

    def create(self, validated_data):
        validated_data.pop('password_confirm')

        try:
            user = User.objects.create(
                username=validated_data['username'],
                email=validated_data['email'],
                department=validated_data.get('department'),
                contact_number=validated_data.get('contact_number'),
                station_address=validated_data.get('station_address'),
                station=validated_data.get('station'),
                is_verified=True,
                role='department_admin'
            )
            user.set_password(validated_data['password'])
            user.save()
        except Exception as e:
            raise serializers.ValidationError({
                "non_field_errors": f"An unexpected error occurred: {str(e)}"
            })

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
        fields = ['username', 'email', 'contact_number', 'department', 'station', 'station_address', 'address', 'password', 'password_confirm', 'is_verified']

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
            contact_number=validated_data.get('contact_number'),
            department=validated_data.get('department'),
            station=validated_data.get('station'),
            station_address=validated_data.get('station_address'),
            address=validated_data.get('address'),
            supervisor_id=supervisor.id,
            is_verified=False,
            role='worker',
        )
        user.set_password(validated_data['password'])
        user.is_email_verified = False  # Mark as unverified initially

        user.save()

        

        return user

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        username_or_email = attrs.get('username')
        password = attrs.get('password')
        user = authenticate(
            request=self.context.get('request'),
            username=username_or_email,
            password=password
        )

        if not user:
            raise ValidationError(
                {"detail": "Invalid credentials. Please try again."},
                code=status.HTTP_401_UNAUTHORIZED
            )

        if not user.is_active:
            raise ValidationError(
                {"detail": "User account is disabled."},
                code=status.HTTP_403_FORBIDDEN
            )

        self.user = user
        data = super().validate(attrs)

        # Add custom fields to the response
        account_type = get_account_type(self.user)

        data.update({
            'user_id': self.user.id,
            'username': self.user.username,
            'email': self.user.email,
            'address': getattr(self.user, 'address', None),
            'coordinates': getattr(self.user, 'coordinates', None),
            'contact_number': getattr(self.user, 'contact_number', None),
            'account_type': account_type,
            'is_email_verified': getattr(self.user, 'is_email_verified', False),
            'is_verified': getattr(self.user, 'is_verified', False),
            'score': getattr(self.user, 'score', None),
        })

        if account_type in ['department_admin', 'worker']:
            data.update({
                'department': str(self.user.department_id) if self.user.department else None,
                'supervisor': str(self.user.supervisor_id) if self.user.supervisor_id else None,
                'station_address': getattr(self.user, 'station_address', None),
                'station': getattr(self.user, 'station', None),
            })

        return data


    


class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
 
        refresh_token = attrs['refresh']
        token = RefreshToken(refresh_token)
        user_id = token['user_id']
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise ValidationError({"detail": "User not found."})
        account_type = get_account_type(self.user)
        data.update({
            'user_id': self.user.id,
            'username': self.user.username,
            'email': self.user.email,
            'address': getattr(self.user, 'address', None),
            'coordinates': getattr(self.user, 'coordinates', None),
            'contact_number': getattr(self.user, 'contact_number', None),
            'account_type': account_type,
            'is_email_verified': getattr(self.user, 'is_email_verified', False),
            'is_verified': getattr(self.user, 'is_verified', False),
            'score': getattr(self.user, 'score', 50),
            'violation': getattr(self.user, 'violation', 0),
        })

        if account_type in ['department_admin', 'worker']:
            data.update({
                'department': str(self.user.department_id) if self.user.department else None,
                'station_address': getattr(self.user, 'station_address', None),
                'station': getattr(self.user, 'station', None),
        })

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
        fields = ['username', 'contact_number', 'is_verified', 'violation', 'role', 'account_status', 'address', 'email', 'id', 'date_joined', 'score', 'supervisor_id']

    # def get_full_name(self, obj):
    #     return f"{obj.first_name} {obj.last_name}"

# class UserProfileSerializer(serializers.ModelSerializer):
#     full_name = serializers.SerializerMethodField()

#     class Meta:
#         model = User
#         fields = ['full_name', 'email', 'contact_number', 'role']  # Only include the desired fields

#     def get_full_name(self, obj):
#         return f"{obj.first_name} {obj.last_name}"

class UserProfileSerializer(serializers.ModelSerializer):
#     # full_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['username', 'email', 'contact_number', 'role', 'station', 'station_address', 'department_id']  # Only include the desired fields

    # def get_full_name(self, obj):
    #     return f"{obj.first_name} {obj.last_name}"


class GetWorkerSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['username', 'contact_number', 'is_verified', 'violation', 'role', 'account_status', 'address', 'email', 'id', 'department']
