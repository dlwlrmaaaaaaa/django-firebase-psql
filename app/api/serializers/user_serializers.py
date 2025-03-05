from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import Token
from rest_framework_simplejwt.views import TokenObtainPairView
from ..utils import get_account_type, generate_firebase_token
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from rest_framework import status
from firebase_admin.exceptions import FirebaseError
import ipaddress
from django.conf import settings
from django.contrib.auth import authenticate
from rest_framework import serializers
from ..models import Department, UserSession
from app.firebase import db
import logging
from django.core.mail import send_mail
import random
from django.core.validators import RegexValidator
from django.core.validators import validate_email
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
        required=False,
        allow_blank=False,
        validators=[UniqueValidator(queryset=User.objects.all(), message="This contact number is already in use.")]
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password_confirm', 'contact_number', 'address', 'coordinates', 'ipv', 'score']

    def validate(self, attrs):
        """Ensure password confirmation matches"""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({'password_confirm': 'Passwords do not match.'})
        return attrs

    def validate_ipv(self, value):
        """Validate IP Address format"""
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise serializers.ValidationError("Invalid IP address format.")
        return value

    def validate_email(self, value):
 
        try:
            validate_email(value)
        except ValidationError:
            raise serializers.ValidationError("Enter a valid email address.")

        # Split the domain part from the email.
        try:
            local_part, domain = value.rsplit('@', 1)
        except ValueError:
            raise serializers.ValidationError("Enter a valid email address.")

        # Split the domain into parts.
        domain_parts = domain.split('.')
        if len(domain_parts) < 2:
            raise serializers.ValidationError("Enter a valid email address.")

        # For example, enforce that the TLD is exactly "com"
        if domain_parts[-1].lower() != "com":
            raise serializers.ValidationError("Email must end with .com")

        return value



    def create(self, validated_data):
        """Create user and save data to Firestore"""
        user = User(
            username=validated_data['username'],
            email=validated_data['email'],
            role='citizen',
            contact_number=validated_data.get('contact_number'),
            address=validated_data.get('address'),
            coordinates=validated_data.get('coordinates'),
            ipv=validated_data.get('ipv'),
            score=50  # Default score
        )
        user.set_password(validated_data['password'])
        user.save()

        # Save non-sensitive data to Firestore
        user_data = {
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'contact_number': user.contact_number,
            'address': user.address,
            'coordinates': user.coordinates,
            'ipv': user.ipv,
            'score': user.score
        }
        
        collection_path = 'users_info'
        try:
            db.collection(collection_path).document(user.username).set(user_data)
        except Exception as e:
            print(f"Firestore Error: {e}")

        return user

    def update(self, instance, validated_data):
        """Update user details"""
        password = validated_data.pop('password', None)
        password_confirm = validated_data.pop('password_confirm', None)

        if password:
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
class GetWorkersSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

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
        fields = ['username', 'email', 'contact_number', 'department', 'station', 'station_address', 'password', 'password_confirm', 'is_verified']

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({"password": "Password fields did not match." })
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        supervisor = self.context['request'].user
    
        user = User(
            username=validated_data['username'],
            email=validated_data['email'],
            contact_number=validated_data.get('contact_number'),
            department=validated_data.get('department'),
            station=validated_data.get('station'),
            station_address=validated_data.get('station_address'),
            address=validated_data.get('address'),
            supervisor_id=supervisor.id,
            is_verified=True,
            role='worker',
        )      
        print("Registration Data: ", validated_data)
        user.set_password(validated_data['password'])
        user.is_email_verified = False 

        user.save()

        

        return user
    


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        logger = logging.getLogger(__name__)

        print("Starting token validation...")

        username = attrs.get('username')
        
        # Try to find the user by email (avoid SQL injection)
        try:
            username_or_email = User.objects.get(email=username)  # Can also try by username if needed
        except User.DoesNotExist:
            print(f"User not found: {username}")
            raise ValidationError({"detail": "Invalid credentials. Please try again."}, 
                                  code=status.HTTP_401_UNAUTHORIZED)
        
        password = attrs.get('password')

        # Check if username and password are present
        if not username_or_email or not password:
            print(f"Missing credentials: username_or_email={username_or_email}, password={password}")
            raise ValidationError({"detail": "Both username/email and password are required."}, 
                                  code=status.HTTP_400_BAD_REQUEST)
        
        if not username_or_email.is_email_verified and username_or_email.role == 'citizen':
            otp = self.generate_otp()
            self.send_verification_email(username_or_email.email, otp)
            
            username_or_email.otp = otp
            username_or_email.save()
            return {
                "is_email_verified": False,
            }
        # Try to authenticate the user
        print(f"Attempting to authenticate user: {username_or_email}")
        user = authenticate(
            request=self.context.get('request'),
            username=username_or_email.username,  # Ensure you use the correct identifier here
            password=password
        )

        # Debug the result of authentication
        if not user:
            print(f"Authentication failed for user: {username_or_email}")
            raise ValidationError(
                {"detail": "Invalid credentials. Please try again."},
                code=status.HTTP_401_UNAUTHORIZED
            )

        if not user.is_active:
            print(f"Inactive user attempted login: {username_or_email}")
            raise ValidationError(
                {"detail": "User account is disabled."},
                code=status.HTTP_403_FORBIDDEN
            )

        self.user = user
        data = super().validate(attrs)

        print(f"User authenticated successfully: {user}")

        # Add custom fields to the response
        account_type = get_account_type(self.user)

        # Debug user data before updating response
        print(f"Populating custom user data for: {self.user.username}")
        print(f"Account type: {account_type}")

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
            'firebase_token': generate_firebase_token(self.user)
        })
        
        if account_type in ['department_admin', 'worker']:
            print(f"Adding department and supervisor details for: {self.user.username}")
            data.update({
                'department': str(self.user.department_id) if self.user.department else None,
                'supervisor': str(self.user.supervisor_id) if self.user.supervisor_id else None,
                'station_address': getattr(self.user, 'station_address', None),
                'station': getattr(self.user, 'station', None),
            })

        return data
    def generate_otp(self):
        return random.randint(100000, 999999)
    
    def send_verification_email(self, email, otp):
        subject = "Verify your email"
        message = (
            f"<html>"
            f"<body>"
            f"<p style='font-weight: bold; color: #0C3B2D; text-align: left; font-size: 1.25em; '>Verify your account. </p>"
            f"<p style='text-align: center; font-size: 0.85em; '>Your CRISP OTP code is:</p>"
            f"<p style='font-weight: bolder; color: #0C3B2D; text-align: center; font-size: 2em; '>{otp}</p>"
            f"<p style='text-align: center; font-size: 0.75em; '>Valid for 15 mins. NEVER share this code with others. <br>If you did not request this, please ignore this email.</p>"
            f"<p style='text-align: left; font-size: 0.75em; '>Best regards,<br>The CRISP Team</p>"
            f"</body>"
            f"</html>"
        )
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [email]

        send_mail(subject, message, from_email, recipient_list, html_message=message)


class ForgotPasswordSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    class Meta: 
        model = User
        fields = ['email']
    
    def validate(self, attrs):
        email = attrs['email']
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"email": "User with this email does not exist."})
        otp = self.generate_otp()
        user.otp = otp
        user.save()
        self.send_verification_email(email, otp)    
        return {"message": "An OTP has been sent to your email."}

    def generate_otp(self):
        return random.randint(100000, 999999)
    
    def send_verification_email(self, email, otp):
        subject = "Verify your email"
        message = (
            f"<html>"
            f"<body>"
            f"<p style='font-weight: bold; color: #0C3B2D; text-align: left; font-size: 1.25em; '>Change Password Request</p>"
            f"<p style='text-align: center; font-size: 0.85em; '>Your CRISP OTP code is:</p>"
            f"<p style='font-weight: bolder; color: #0C3B2D; text-align: center; font-size: 2em; '>{otp}</p>"
            f"<p style='text-align: center; font-size: 0.75em; '>Valid for 15 mins. NEVER share this code with others. <br>If you did not request this, please ignore this email.</p>"
            f"<p style='text-align: left; font-size: 0.75em; '>Best regards,<br>The CRISP Team</p>"
            f"</body>"
            f"</html>"
        )
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [email]

        send_mail(subject, message, from_email, recipient_list, html_message=message)

class VerifyOtpSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['otp', 'email']
    
    def validate(self, attrs):
        otp = attrs['otp']
        email = attrs['email']
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"email": "User not found."})
        if user.otp != otp:
            raise serializers.ValidationError({"otp": "Invalid OTP."})
        return {"message": "OTP verified successfully."}

class ResetPasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(required=True, write_only=True)
    password_confirm = serializers.CharField(required=True, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'password_confirm']
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, attrs):
        password = attrs.get('password')  
        password_confirm = attrs.pop('password_confirm') 
        email = attrs.get('email')
        if not password or not password_confirm:
            raise serializers.ValidationError({"password": "Password fields cannot be empty."})

        if password != password_confirm:
            raise serializers.ValidationError({"password": "Passwords do not match."})

        user = User.objects.filter(email=email).first()  # Use `.filter().first()` to avoid exceptions
        if not user:
            raise serializers.ValidationError({"email": "User with this email does not exist."})

        user.set_password(password)
        user.otp = None  # Clear OTP after successful reset
        user.save()

        return {"message": "Password reset successfully."}

class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
 
        refresh_token = attrs['refresh']
        token = RefreshToken(refresh_token)
        user_id = token['user_id']
        user = User.objects.get(id=user_id)

        account_type = get_account_type(user)
        data.update({
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'address': getattr(user, 'address', None),
            'coordinates': getattr(user, 'coordinates', None),
            'contact_number': getattr(user, 'contact_number', None),
            'account_type': account_type,
            'is_email_verified': getattr(user, 'is_email_verified', False),
            'is_verified': getattr(user, 'is_verified', False),
            'score': getattr(user, 'score', 50),
            'violation': getattr(user, 'violation', 0),
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
        fields = ['username', 'contact_number', 'is_verified', 'violation', 'role', 'account_status', 'station', 'address', 'email', 'id', 'date_joined', 'score', 'supervisor_id']

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
    username = serializers.CharField(
        validators=[
            RegexValidator(
                r'^[\w.@+\-\s]+$',  # Added \s to allow spaces
                'Username may only contain letters, numbers, spaces, and @/./+/-/_ characters.'
            ),
        ],
        error_messages={
            'invalid': 'Please enter a valid username. Only letters, numbers, spaces, and @/./+/-/_ characters are allowed.',
            'required': 'Username is required',
            'max_length': 'Username is too long',
        }
    )
    class Meta:
        model = User
        fields = ['username', 'email', 'contact_number', 'role', 'station', 'station_address', 'department_id']  # Only include the desired fields

    # def get_full_name(self, obj):
    #     return f"{obj.first_name} {obj.last_name}"


class GetWorkerSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['username', 'contact_number', 'is_verified', 'violation', 'role', 'account_status', 'address', 'email', 'id', 'department']

