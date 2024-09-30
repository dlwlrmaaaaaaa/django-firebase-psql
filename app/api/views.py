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
from .serializers.user_serializers import CitizenSerializer, DepartmentAdminSerializer
from .serializers.report_serializers import AddReportSerializer, UpdateReportSerializer
from .models import Report
from .serializers.otp_serializer import OTPVerificationSerializer
from django.core.mail import send_mail
from django.http import HttpResponse
import random
from django.conf import settings

from django.shortcuts import redirect
from django.urls import reverse
from django.contrib.auth import get_user_model

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
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Send OTP after successful registration
        otp = random.randint(100000, 999999)  # Generate a random 6-digit OTP

        user.otp = str(otp)  # Store as string to preserve leading zeros
        user.save()

        self.send_verification_email(user.email, otp)

        return redirect('verify')  # Redirect to verification page
        
        
    
    def send_verification_email(self, email, otp):
        subject = "Verify your email"
        message = f"Your OTP is: {otp} gago ka hahaha"  # Message to be sent
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [email]
        send_mail(subject, message, from_email, recipient_list)
    
    
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
        # Return a message when the verification page is accessed
        return Response({
            "message": "An email containing the OTP has been sent to your email address."
        }, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)  # Validate incoming data
        
        otp_input = serializer.validated_data['otp']  # Extract the OTP

        try:
            # Fetch the user based on the OTP
            user = User.objects.get(otp=otp_input)  
            
            if user.otp == otp_input:  # Compare the input OTP with the stored one
                    user.otp = None  # Clear the OTP after verification
                    user.is_email_verified = True  # Set is_email_verified to True
                    user.save()  # Save changes to the database
                    
                    return HttpResponse(""" 
                        <html>
                        <head>
                            <script>
                                alert('OTP verified successfully.');
                                setTimeout(function() {
                                    window.location.href = '/api/token/';  
                                }, 5000);  // Redirect after 5 seconds
                            </script>
                        </head>
                        <body>
                        </body>
                        </html>
                    """)

        except User.DoesNotExist:
                return Response({"message": "Invalid OTP"}, status=status.HTTP_404_NOT_FOUND)