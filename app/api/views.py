from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from rest_framework import generics
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers.user_serializers import CustomTokenObtainPairSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated 
from rest_framework import status
from .permission import IsSuperAdmin, IsDepartmentAdmin, IsCitizen
from .serializers.user_serializers import CitizenSerializer, DepartmentAdminSerializer, VerifyPasswordSerializer, ChangePasswordSerializer
from .serializers.report_serializers import AddReportSerializer, UpdateReportSerializer
from .models import Report
from .serializers.otp_serializer import OTPVerificationSerializer
from django.core.mail import send_mail
from django.http import HttpResponse
import random
from django.conf import settings

from django.shortcuts import redirect, get_object_or_404
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework.exceptions import PermissionDenied
User = get_user_model()


class AssignRoleView(generics.CreateAPIView):
    permission_classes = [IsAuthenticated, IsSuperAdmin]  # Only super admins can assign roles

    def post(self, request, user_id):
        try:
            user = User.objects.get(pk=user_id)
            new_role = request.data.get('role')

            if new_role in ['super_admin', 'department_admin']:
                user.role = new_role
                user.save()
                return Response({'message': f'Role updated to {new_role}'}, status=200)
            else:
                return Response({'error': 'Invalid role'}, status=400)

        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=404)

class CitizenRegitsration(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = CitizenSerializer
    
    def create(self, request, *args, **kwargs):
        print("Request data:", request.data)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        otp = random.randint(100000, 999999)  

        user.otp = str(otp) 
        user.save()

        try:
            self.send_verification_email(user.email, otp)
        except Exception as e:
            return Response({"error": "Failed to send verification email"}, status=500)

        return redirect('verify')
    
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
    permission_classes = [IsAuthenticated, IsDepartmentAdmin]
    serializer_class = DepartmentAdminSerializer


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

    
class ReportView(generics.CreateAPIView):
    permission_classes = [IsAuthenticated, IsCitizen]
    serializer_class = AddReportSerializer

class DeleteReportView(generics.DestroyAPIView):
    query_set = Report.objects.all()
    permission_class = [IsAuthenticated, IsCitizen, IsSuperAdmin]

    def get_object(self):
        report_id = self.kwargs.get('report_id')
        return get_object_or_404(Report, report_id=report_id)
    
    def delete(self, request, *args, **kwargs):
        report = self.get_object()

        # SuperAdmin role can delete any report
        if report.user_id != request.user:
            return Response({"error": "You are not authorized to delete this report."}, status=status.HTTP_403_FORBIDDEN)
        
        if request.user.role.lower() == 'super_admin' or 'superadmin':
            report.delete()
            return Response({"message": "Report deleted successfully."}, status=status.HTTP_200_OK)
        
        if request.user.role.lower() == 'citizen':
            report.delete()
            return Response({"message": "Your report has been deleted successfully."}, status=status.HTTP_200_OK)

        raise PermissionDenied({"error": "You do not have permission to delete this report."})


class UpdateReportView(generics.UpdateAPIView):
    queryset = Report.objects.all()
    permission_classes = [AllowAny]
    serializer_class = UpdateReportSerializer

    def put(self, request, report_id):
        try:
            report = Report.objects.get(report_id=report_id)
        except Report.DoesNotExist:
            return Response({"error": "Report not found"}, status=status.HTTP_404_NOT_FOUND)
            
        serializer = UpdateReportSerializer(report, data=request.data, context={'request': request})
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SomeView(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdmin]  # Or any other permission class

    def get(self, request):
        # Your logic here
        return Response({"message": "This is a super admin view."}, status=status.HTTP_200_OK)
    

class OTPVerificationView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = OTPVerificationSerializer  # Use the updated serializer

    def get(self, request, *args, **kwargs):    
        return Response({
            "message": "An email containing the OTP has been sent to your email address."
        }, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)  # Validate incoming data
        
        otp_input = serializer.validated_data['otp']  # Extract the OTP
        email = serializer.validated_data['email']
    
        try:
            # Fetch the user based on the OTP
            user = User.objects.get(email=email)  

            if user.is_email_verified:
                return Response({"message": "Email already verified."}, status=status.HTTP_400_BAD_REQUEST)

            if user.otp == otp_input:  # Compare the input OTP with the stored one
                    user.otp = None  # Clear the OTP after verification
                    user.is_email_verified = True  # Set is_email_verified to True
                    user.save()  # Save changes to the database
                    
                    return Response({"message": "Your Email has been verified."}, status=status.HTTP_200_OK)
            else:
                return Response({"message": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
                return Response({"message": "Invalid OTP"}, status=status.HTTP_404_NOT_FOUND)
        
class UserProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = CitizenSerializer  # Use the same serializer you use for registration or create a new one

    def get_object(self):
        return self.request.user  # Retrieve the authenticated user

    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)  # partial=True allows partial updates (e.g. only updating email)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class VerifyPasswordView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = VerifyPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        password = serializer.validated_data['password']
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
        user.set_password(serializer.validated_data['new_password'])
        user.save()

        return Response({"message": "Password changed successfully."}, status=status.HTTP_200_OK)