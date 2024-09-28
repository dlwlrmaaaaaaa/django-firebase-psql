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
from .serializers.report_serializers import ReportSerializer


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
    serializer_class = ReportSerializer

class SomeView(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdmin]  # Or any other permission class

    def get(self, request):
        # Your logic here
        return Response({"message": "This is a super admin view."}, status=status.HTTP_200_OK)

