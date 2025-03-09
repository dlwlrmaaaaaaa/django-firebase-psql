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
from .serializers.department_serializer import DepartmentSerializer
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
    GetWorkersSerializer,
    ForgotPasswordSerializer,
    VerifyOtpSerializer,
    ResetPasswordSerializer
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
from app.app.firebase import db
from firebase_admin import firestore
from django.http import JsonResponse
from .models import User, Department
import datetime
from datetime import timedelta
User = get_user_model()
import csv
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


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import status

import tensorflow as tf
from tensorflow.keras.models import load_model
import numpy as np
from PIL import Image
import io
import os
    
# Load the trained model
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Get the directory of the current file
MODEL_PATH = os.path.join(BASE_DIR, "fixed_model.h5")  # Construct full path to model

model = load_model(MODEL_PATH)

# Define class labels
CLASS_NAMES = ["Fallen Tree", "Fire Accident", "Flood", "Graphic Violence", "Nudity", "Others", "Pothole", "Road Accident", "Street Light"]

def preprocess_image(image):
    """
    Preprocess the input image to match the model's expected format.
    """
    image = image.resize((224, 224))  # Resize to match model input shape
    image = np.array(image) / 255.0   # Normalize pixel values (0-1)
    image = np.expand_dims(image, axis=0)  # Add batch dimension
    return image

def predict_image(image):
    """
    Run prediction on the image and return the class label & confidence score.
    """
    processed_image = preprocess_image(image)
    predictions = model.predict(processed_image)[0]  # Get predictions
    class_index = np.argmax(predictions)  # Get the highest confidence index
    confidence = predictions[class_index]  # Confidence score

    return {"class": CLASS_NAMES[class_index], "confidence": float(confidence)}

class ImageClassificationAPIView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = []
    authentication_classes= []
    def post(self, request, *args, **kwargs):
        if 'image' not in request.FILES:
            return Response({"error": "No image file provided"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Read and process the image
            image_file = request.FILES['image']
            image = Image.open(io.BytesIO(image_file.read()))

            # Ensure image is RGB format (handle grayscale or other formats)
            image = image.convert("RGB")

            # Make a prediction
            result = predict_image(image)
            
            return Response(result, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    
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
    authentication_classes = []
    serializer_class = CitizenSerializer

    def create(self, request, *args, **kwargs):
        print("Request data:", request.data)
        serializer = self.get_serializer(data=request.data)
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
    permission_classes = [AllowAny]
    queryset = Department.objects.all()
    serializer_class = DepartmentList

class DepartmentView(generics.DestroyAPIView):
    permission_classes = [IsSuperAdmin]
    queryset = Department.objects.all()
    serializer_class = DepartmentSerializer

class DepartmentCreateView(generics.CreateAPIView):
    permission_classes = [IsSuperAdmin]
    queryset = Department.objects.all()
    serializer_class = DepartmentSerializer
    

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
    authentication_classes = []
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
        print('Request data:', request.data)
        user = self.get_object()
        serializer = self.get_serializer(
            user, data=request.data, partial=True
        )  
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        print('Validation errors:', serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DeleteAccount(APIView):
    permission_classes = [IsSuperAdmin]  # Ensure only super admins can delete other accounts

    def delete(self, request, *args, **kwargs):
        # Get the user ID from the request parameter (assuming it's passed in the URL)
        user_id = self.kwargs.get('user_id')

        try:
            # Find the user by ID
            user = User.objects.get(id=user_id)

            # Store deleted account data to Firebase (in a 'deletedAccounts' collection)
            deleted_account_data = {
                'username': user.username,
                'email': user.email,
                'date_deleted': firestore.SERVER_TIMESTAMP,
            }

            # Store to Firestore
            db.collection('deletedAccounts').add(deleted_account_data)

            # Delete the user account
            user.delete()

            return Response({"result": "User deleted successfully"}, status=200)
        
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=404) 


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
        VerifyAccount.objects.filter(user=request.user).delete()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)


          
        # Save the new VerifyAccount instance
        verify_account = serializer.save(user=request.user)

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

class DeclineVerifyAccount(generics.UpdateAPIView):
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
            instance.is_verified = False
            instance.score = instance.score 

            # Save changes to the database
            instance.save(update_fields=["is_verified", "score"])

            # Save using serializer to handle extra validation or custom logic
            serializer = self.get_serializer(instance, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)

            print(
                f"After update: is_verified={instance.is_verified}, score={instance.score}"
            )
            return Response(
                {"detail": "User verification declined and score updated."},
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
    authentication_classes = []

class SuperAdminViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = User.objects.filter(role="superadmin")  # Filter for Admins
    serializer_class = WorkerSerializers
    # permission_classes = [IsAuthenticated]
    permission_classes = [AllowAny]
    authentication_classes = []

class WorkersViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = User.objects.filter(role="worker")
    serializer_class = WorkerSerializers
    # permission_classes = [IsAuthenticated]
    permission_classes = [AllowAny]
    authentication_classes = []

class UsersViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = UsersSerializer
    permission_classes = [AllowAny]
    authentication_classes = []
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
    
class GetWorkerUnderDepartmentAdmin(generics.GenericAPIView):
    serializer_class = GetWorkersSerializer
    permission_classes = [IsDepartmentAdmin]

    def get(self, request, *args, **kwargs):
        # Ensure the user has the right permission (department admin)
        user = self.request.user
        if not user.department:
            return Response({"detail": "No department found for user."}, status=400)

        workers = User.objects.filter(role="worker", supervisor_id=user.id)
        serializer = self.get_serializer(workers, many=True)
        return Response(serializer.data)
    

def get_department_details(request, assigned_to_id):
    try:
        # Step 1: Get the user with the given ID
        user = User.objects.filter(id=assigned_to_id).first()
        if not user:
            return JsonResponse({"department_id": "Unknown", "department_name": "Unknown"})

        # Step 2: Get the department_id from the user
        department_id = user.department_id
        
        # Step 3: Get the department name using the department_id
        department = Department.objects.filter(id=department_id).first()
        if not department:
            return JsonResponse({"department_id": "Unknown", "department_name": "Unknown"})

        # Return both department_id and department_name
        return JsonResponse({
            "department_id": department_id,
            "department_name": department.name
        })
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
    
class VerifyOTPView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = VerifyOtpSerializer
    authentication_classes = []
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"message": "OTP verified successfully."}, status=200)

class ForgotPasswordView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = ForgotPasswordSerializer
    authentication_classes = []
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"message": "Password reset code sent succesfully"}, status=200)

class ResetPasswordView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = ResetPasswordSerializer
    authentication_classes = []
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"message": "Password reset successfully"}, status=200)

# class ExportWeeklyReports(APIView):
#     permission_classes = [AllowAny]
#     def get(self, request, *args, **kwargs):
#         try:
#             today = datetime.datetime.today() 
#             start_of_month = datetime.datetime(today.year, today.month, 1)
#             next_month = today.month % 12 + 1  # Handle December (12 → 1)
#             next_month_year = today.year + (1 if today.month == 12 else 0)
#             end_of_month = datetime.datetime(next_month_year, next_month, 1) - datetime.timedelta(seconds=1)

#             reports_ref = db.collection('reports')
#             categories = reports_ref.list_documents()

#             reports = []

#             for category in categories: 
#                 category_name = category.id
#                 docs = category.collection(category_name).where('timestamp', '>=', start_of_month).where('timestamp', '<=', end_of_month).stream()
                
#                 for doc in docs:
#                     data = doc.to_dict()

#                     # Convert Firestore Timestamp to Python datetime
#                     timestamp = data.get('timestamp')
#                     if isinstance(timestamp, firestore.Timestamp):
#                         timestamp = timestamp.to_datetime()

#                     reports.append({
#                         "Report ID": doc.id,
#                         "Category": category_name,  # Add category name
#                         "Timestamp": timestamp,
#                         "Details": data.get('details', 'No details')
#                     })

#             if not reports:
#                 return Response({"message": "No reports found for this month"}, status=200)

#             df = pd.DataFrame(reports)

#             # Export as CSV
#             response = HttpResponse(content_type='text/csv')
#             response['Content-Disposition'] = 'attachment; filename="monthly_reports.csv"'
#             df.to_csv(response, index=False)
            
#             return response

#         except Exception as e:
#             return Response({"error": str(e)}, status=500)
        
class ExportAllReports(APIView):
    permission_classes = [IsSuperAdmin]

    def get(self, request, *args, **kwargs):
        try:
            db = firestore.client()
            reports_ref = db.collection('reports')
            categories = reports_ref.list_documents()

            reports = []

            for category in categories:
                category_name = category.id  # fire_accident, fallen_tree, etc.

                # 🔹 Get the 'reports' subcollection inside each category
                reports_collection = category.collection('reports')
                docs = reports_collection.stream()

                for doc in docs:
                    data = doc.to_dict()
                    reports.append(data)

            if not reports:
                return Response({"message": "No reports found"}, status=200)

            # 🔹 Convert to Pandas DataFrame
            df = pd.DataFrame(reports)

            # 🔹 Export as CSV
            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="all_reports.csv"'
            df.to_csv(response, index=False)

            return response

        except Exception as e:
            return Response({"error": str(e)}, status=500)


class BackupData(APIView):
    permission_classes = [IsSuperAdmin]

    