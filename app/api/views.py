from django.forms import ValidationError
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from rest_framework import generics, viewsets
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .serializers.user_serializers import (
    CustomTokenObtainPairSerializer,
    CustomTokenRefreshSerializer,
)
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser
from .permission import IsSuperAdmin, IsDepartmentAdmin, IsCitizen
from .serializers.user_serializers import (
    DepartmentList,
    CitizenSerializer,
    GetWorkerSerializer,
    UserProfileSerializer,
    DepartmentAdminSerializer,
    VerifyPasswordSerializer,
    ChangePasswordSerializer,
    WorkerSerializers,
    UsersSerializer,
)
from .serializers.report_serializers import AddReportSerializer, UpdateReportSerializer
from .serializers.fire_serializer import FirePredictionSerializer
from .models import Report
from .models import VerifyAccount
from .serializers.verifyAcc_serializer import VerifyAccountSerializer, VerifyUser
from .serializers.otp_serializer import OTPVerificationSerializer
from django.core.mail import send_mail
from django.http import HttpResponse
import random
from django.conf import settings
from django.utils import timezone
from django.shortcuts import redirect, get_object_or_404
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework.exceptions import PermissionDenied
from .models import Department
import joblib
import pandas as pd
import os
import gdown
import uuid

User = get_user_model()

import os
import joblib
from rest_framework.response import Response
from rest_framework import status
from rest_framework import generics
import pandas as pd
from django.conf import settings
import logging


from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.shortcuts import get_object_or_404
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator


# Set up logging
logger = logging.getLogger(__name__)


class FirePredictionView(generics.CreateAPIView):
    serializer_class = FirePredictionSerializer

    best_rf_model = None

    def load_model(self):
        # Use BASE_DIR for path construction to ensure proper path resolution
        model_path = os.path.join(settings.BASE_DIR, "best_rf_model2.pkl")

        # Log the model path to help debug
        logger.info(f"Attempting to load model from: {model_path}")

        try:
            # Check if the file exists before loading
            if os.path.exists(model_path):
                logger.info(f"Model file found at: {model_path}")
                self.best_rf_model = joblib.load(model_path)
                logger.info("Model loaded successfully")
            else:
                logger.error(f"Model file not found at: {model_path}")
                self.best_rf_model = None
        except Exception as e:
            self.best_rf_model = None
            logger.error(f"Error loading model: {e}")

    def post(self, request):
        # Load the model if it's not already loaded
        if self.best_rf_model is None:
            self.load_model()

        if self.best_rf_model is None:
            return Response(
                {"error": "Model file could not be loaded"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # Serialize and process input data
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Convert the input data into a pandas DataFrame for prediction
        sample_df = pd.DataFrame([serializer.validated_data])

        # Rename columns to match the model's training data
        column_renames = {
            "Wind": "Wind (km/h)",
            "Barometer": "Barometer (mbar)",
            "Precipitation": "Precipitation (%)",
            "Temperature": "Temperature (°C)",
            "Weather_Heavy_rain": "Weather_Heavy rain",
            "Weather_Light_rain": "Weather_Light rain",
            # Add other necessary renames here
            "Weather_Partly_sunny": "Weather_Partly sunny",
            "Weather_Passing_clouds": "Weather_Passing clouds",
            "Weather_Scattered_clouds": "Weather_Scattered clouds",
            "Weather_Thunderstorms_dot": "Weather_Thunderstorms.",
            "Wind_kmh": "Wind (km/h)",
            # Add other mappings as needed
        }
        sample_df.rename(columns=column_renames, inplace=True)

        # Predict the severity level
        try:
            prediction = self.best_rf_model.predict(sample_df)
            predicted_label = ["low", "moderate", "high", "severe"]
            result = predicted_label[prediction[0]]

            return Response({"prediction": result}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AssignRoleView(generics.CreateAPIView):
    permission_classes = [
        IsAuthenticated,
        IsSuperAdmin,
    ]  # Only super admins can assign roles

    def post(self, request, user_id):
        try:
            user = User.objects.get(pk=user_id)
            new_role = request.data.get("role")

            if new_role in ["super_admin", "department_admin"]:
                user.role = new_role
                user.save()
                return Response({"message": f"Role updated to {new_role}"}, status=200)
            else:
                return Response({"error": "Invalid role"}, status=400)

        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=404)


class CitizenRegitsration(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = CitizenSerializer

    def create(self, request, *args, **kwargs):
        print("Request data:", request.data)
        serializer = self.get_serializer(data=request.data)
        # Check if the serializer is valid
        # Check if the serializer is valid
        if not serializer.is_valid():
            print("Validation errors:", serializer.errors)  # Log the errors
            return Response(serializer.errors, status=400)
        try:
            user = serializer.save()

            otp = random.randint(100000, 999999)
            user.otp = str(otp)
            user.save()

            self.send_verification_email(user.email, otp)

        except Exception as e:
            print(
                "Error during user creation or email sending:", str(e)
            )  # Log the error
            return Response(
                {"error": "Internal server error", "details": str(e)}, status=500
            )
        return Response(
            {
                "message": "User registered successfully. Please check your email for the OTP verification.",
                "user_id": user.id,
                "email": user.email
            },
            status=status.HTTP_201_CREATED  
        )

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


class ResendOtp(generics.UpdateAPIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")

        try:
            user = User.objects.get(email=email, is_verified=False)
        except User.DoesNotExist:
            return Response({"error": "User not found or already verified"}, status=404)
        otp = random.randint(100000, 999999)
        user.otp = otp
        user.otp_created_at = timezone.now()
        user.save()

        CitizenRegitsration.send_verification_email(self, user.email, otp)

        return Response({"message": "OTP resent successfully"}, status=200)

class ResendOtpDepartment(generics.UpdateAPIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")

        try:
            user = User.objects.get(email=email, is_email_verified=False)
        except User.DoesNotExist:
            return Response({"error": "User not found or already verified"}, status=404)

        otp = random.randint(100000, 999999)
        user.otp = otp
        user.otp_created_at = timezone.now()
        user.save()
        self.send_verification_email(user.email, otp)

        return Response({"message": "OTP resent successfully"}, status=200)

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


class DepartmentRegistration(generics.CreateAPIView):
    permission_classes = [IsAuthenticated, IsSuperAdmin]
    serializer_class = DepartmentAdminSerializer


class WorkerRegistration(generics.CreateAPIView):
    permission_classes = [IsDepartmentAdmin]
    serializer_class = WorkerSerializers

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        department_admin = self.request.user
        station_address = department_admin.station_address

        # Check if the serializer is valid
        if not serializer.is_valid():
            return Response(serializer.errors, status=400)

        try:
            # Create the worker user and set the address from the department admin
            user = serializer.save(station_address=station_address)
            user.is_verified = False  # Ensure the account is not verified yet
            user.save()  # Save the user after assigning the address

            # Generate a verification link
            verification_link = self.generate_verification_link(user)

            # Send the verification email
            self.send_verification_email(user.email, verification_link)

        except Exception as e:
            return Response(
                {"error": "Internal server error", "details": str(e)}, status=500
            )

        return Response(
            {
                "message": "Account created successfully. Verification link sent to email."
            },
            status=201,
        )

    def generate_verification_link(self, user):
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        verification_url = reverse("verify-email")  # Name of the verification endpoint
        link = f"{self.request.scheme}://{self.request.get_host()}{verification_url}?uid={uid}&token={token}"
        return link

    def send_verification_email(self, email, link):
        subject = "Verify Your Email"
        message = (
            f"<html>"
            f"<body>"
            f"<p style='font-weight: bold; color: #0C3B2D; text-align: left; font-size: 1.25em;'>Verify your account.</p>"
            f"<p style='text-align: center; font-size: 0.85em;'>Click the link below to verify your account:</p>"
            f"<p style='text-align: center;'><a href='{link}' style='font-weight: bold; color: #1D70B8;'>{link}</a></p>"
            f"<p style='text-align: center; font-size: 0.75em;'>This link is valid for 24 hours. If you did not request this, please ignore this email.</p>"
            f"<p style='text-align: left; font-size: 0.75em;'>Best regards,<br>The CRISP Team</p>"
            f"</body>"
            f"</html>"
        )
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [email]

        send_mail(subject, message, from_email, recipient_list, html_message=message)


class VerifyWorkerEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        uid = request.GET.get("uid")
        token = request.GET.get("token")

        try:
            # Decode the user ID
            user_id = urlsafe_base64_decode(uid).decode()
            user = get_object_or_404(User, pk=user_id)

            # Check if the token is valid
            if default_token_generator.check_token(user, token):
                user.is_verified = True
                user.save()
                return Response(
                    {"message": "Your email has been verified!"}, status=200
                )

            return Response({"error": "Invalid or expired token."}, status=400)

        except Exception as e:
            return Response({"error": "Invalid request."}, status=400)

class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        uid = request.GET.get("uid")
        token = request.GET.get("token")

        try:
            # Decode the user ID
            user_id = urlsafe_base64_decode(uid).decode()
            user = get_object_or_404(User, pk=user_id)

            # Check if the token is valid
            if default_token_generator.check_token(user, token):
                user.is_verified = True
                user.save()
                return Response(
                    {"message": "Your email has been verified!"}, status=200
                )

            return Response({"error": "Invalid or expired token."}, status=400)

        except Exception as e:
            return Response({"error": "Invalid request."}, status=400)

class DepartmentListView(generics.ListAPIView):
    permission_classes = [IsSuperAdmin]
    queryset = Department.objects.all()
    serializer_class = DepartmentList


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


class MyRefreshTokenPair(TokenRefreshView):
    serializer_class = CustomTokenRefreshSerializer


class ReportView(generics.CreateAPIView):
    permission_classes = [IsAuthenticated, IsCitizen]
    serializer_class = AddReportSerializer


class DeleteReportView(generics.DestroyAPIView):
    query_set = Report.objects.all()
    permission_class = [IsCitizen, IsSuperAdmin]

    def get_object(self):
        report_id = self.kwargs.get("report_id")
        return get_object_or_404(Report, report_id=report_id)

    def delete(self, request, *args, **kwargs):
        report = self.get_object()

        # SuperAdmin role can delete any report
        if report.user_id != request.user.id:
            return Response(
                {"error": "You are not authorized to delete this report."},
                status=status.HTTP_403_FORBIDDEN,
            )

        if request.user.role.lower() == "super_admin" or "superadmin":
            report.delete()
            return Response(
                {"message": "Report deleted successfully."}, status=status.HTTP_200_OK
            )

        if request.user.role.lower() == "citizen":
            report.delete()
            return Response(
                {"message": "Your report has been deleted successfully."},
                status=status.HTTP_200_OK,
            )

        raise PermissionDenied(
            {"error": "You do not have permission to delete this report."}
        )


class UpdateReportView(generics.UpdateAPIView):
    queryset = Report.objects.all()
    permission_classes = [AllowAny]
    serializer_class = UpdateReportSerializer

    def put(self, request, report_id):
        try:
            report = Report.objects.get(report_id=report_id)
        except Report.DoesNotExist:
            return Response(
                {"error": "Report not found"}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = UpdateReportSerializer(
            report, data=request.data, context={"request": request}
        )

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SomeView(APIView):
    permission_classes = [
        IsAuthenticated,
        IsSuperAdmin,
    ]  # Or any other permission class

    def get(self, request):
        # Your logic here
        return Response(
            {"message": "This is a super admin view."}, status=status.HTTP_200_OK
        )


class OTPVerificationView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = OTPVerificationSerializer  # Use the updated serializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)  # Validate incoming data

        otp_input = serializer.validated_data["otp"]  # Extract the OTP
        email = serializer.validated_data["email"]

        try:
            user = User.objects.get(email=email)

            if user.is_email_verified:
                return Response(
                    {"message": "Email already verified."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if user.otp == otp_input:  # Compare the input OTP with the stored one
                user.otp = None  # Clear the OTP after verification
                user.is_email_verified = True  # Set is_email_verified to True
                user.save()  # Save changes to the database

                return Response(
                    {"message": "Your Email has been verified."},
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"message": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST
                )
        except User.DoesNotExist:
            return Response(
                {"message": "Invalid OTP"}, status=status.HTTP_404_NOT_FOUND
            )


class UserProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserProfileSerializer  # Use the same serializer you use for registration or create a new one

    def get_object(self):
        return self.request.user  # Retrieve the authenticated user

    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(
            user, data=request.data, partial=True
        )  # partial=True allows partial updates (e.g. only updating email)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class UserProfileViewSet(viewsets.ModelViewSet):
#     parser_classes = [MultiPartParser]

#     @action(detail=True, methods=['post'])
#     def upload_profile_image(self, request, pk=None):
#         user = self.get_object()
#         user.profile_image_path = request.FILES.get('profile_image')
#         user.save()
#         return Response({'message': 'Profile image updated successfully', 'profile_image_path': user.profile_image_path.url})


class VerifyPasswordView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = VerifyPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        password = serializer.validated_data["password"]
        user = request.user

        if user.check_password(password):
            return Response({"valid": True}, status=status.HTTP_200_OK)
        else:
            return Response({"valid": False}, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(generics.UpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    def update(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        user.set_password(serializer.validated_data["new_password"])
        user.save()

        return Response(
            {"message": "Password changed successfully."}, status=status.HTTP_200_OK
        )


class VerifyAccountView(generics.CreateAPIView):
    permission_classes = [IsAuthenticated]  # Allow only authenticated users
    serializer_class = VerifyAccountSerializer

    def create(self, request, *args, **kwargs):
        # Initialize the serializer with request data
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)  # Validate the incoming data

        # Save the new VerifyAccount instance
        verify_account = serializer.save()

        return Response(
            {
                "message": "Verification account created successfully.",
                "data": VerifyAccountSerializer(verify_account).data,
            },
            status=status.HTTP_201_CREATED,
        )


class AcceptVerifyAccount(generics.UpdateAPIView):
    queryset = User.objects.all()
    permission_classes = [IsSuperAdmin]
    serializer_class = VerifyUser

    def update(self, request, *args, **kwargs):
        try:
            # Fetch the instance
            instance = self.get_object()

            # Logging for debugging
            print(
                f"Before update: is_verified={instance.is_verified}, score={instance.score}"
            )

            # Update fields
            instance.is_verified = True
            instance.score = (instance.score or 0) + 20  # Ensure score is not None

            # Save changes to the database
            instance.save(update_fields=["is_verified", "score"])

            # Save using serializer to handle extra validation or custom logic
            serializer = self.get_serializer(instance, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)

            # Logging for debugging
            print(
                f"After update: is_verified={instance.is_verified}, score={instance.score}"
            )

            # Return success response
            return Response(
                {"detail": "User successfully verified and score updated."},
                status=status.HTTP_200_OK,
            )
        except ValidationError as e:
            # Handle validation errors
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            # Handle general errors
            print(f"Error: {e}")
            return Response(
                {"detail": "An error occurred while updating the user."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class CitizenViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = User.objects.filter(role="citizen")  # Filter for citizens
    serializer_class = CitizenSerializer
    permission_classes = [IsAuthenticated]
    # permission_classes = [AllowAny]


class DepartmentHeadViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = User.objects.filter(
        role="department_head"
    )  # Filter for department heads
    serializer_class = DepartmentAdminSerializer
    # permission_classes = [IsAuthenticated]
    permission_classes = [AllowAny]


class SuperAdminViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = User.objects.filter(role="superadmin")  # Filter for Admins
    serializer_class = WorkerSerializers
    # permission_classes = [IsAuthenticated]
    permission_classes = [AllowAny]


class WorkersViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = User.objects.filter(role="worker")
    serializer_class = WorkerSerializers
    # permission_classes = [IsAuthenticated]
    permission_classes = [AllowAny]


class UsersViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = UsersSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):

        return User.objects.filter(
            role__in=["citizen", "department_admin", "department_head", "worker"]
        )


class GetWorkerViewSet(generics.GenericAPIView):
    serializer_class = GetWorkerSerializer
    permission_classes = [IsDepartmentAdmin]

    def get_queryset(self):
        user = self.request.user
        if not user.department:
            return User.objects.none()

        return User.objects.filter(role__in=["worker"], department=user.department)
