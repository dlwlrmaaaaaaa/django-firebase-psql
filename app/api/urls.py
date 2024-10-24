from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView
from .views import MyTokenObtainPairView, SomeView, CitizenRegitsration, DeleteReportView, DepartmentRegistration, WorkerRegistration, ReportView, OTPVerificationView, UpdateReportView, UserProfileView, VerifyPasswordView, ChangePasswordView, VerifyAccountView
from rest_framework.routers import DefaultRouter


from .views import (
    MyTokenObtainPairView,
    CitizenViewSet,
    DepartmentHeadViewSet,
    WorkerViewSet, UsersViewSet
)

# Create a router and register our viewsets with it.
router = DefaultRouter()
router.register(r'citizens', CitizenViewSet, basename='citizen')  # Unique basename
router.register(r'deptheads', DepartmentHeadViewSet, basename='depthead')  # Unique basename
router.register(r'workers', WorkerViewSet, basename='worker')  # Unique basename
router.register(r'users', UsersViewSet, basename='user')  # Unique basename


urlpatterns = [
    path('token/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'), ## This is login and generated token
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'), ## this is refresh token where you will get another access token
    path('superadmin-only/', SomeView.as_view(), name='protected_superadmin'),## this is for test auth

    ### This is for Registration
    path('citizen/registration/', CitizenRegitsration.as_view(), name='citizen_registration'),
    path('department_admin/registration/', DepartmentRegistration.as_view(), name='admin_registration'),
    path('worker/registration/', WorkerRegistration.as_view(), name='worker_registration'),

    ### For reports
    path('create-report/', ReportView.as_view(), name='create-report'),


    path('otp/verify/', OTPVerificationView.as_view(), name='verify'),

    ##update reports
    path('reports/<int:report_id>/update/', UpdateReportView.as_view(), name='update-report'),
    path('reports/<uuid:report_id>/delete/', DeleteReportView.as_view(), name='update-report'),

    path('user/profile/', UserProfileView.as_view(), name='user_profile'),
    path('verify-password/', VerifyPasswordView.as_view(), name='verify-password'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),

    path('verify-account/', VerifyAccountView.as_view(), name='verify-account'),

    path('', include(router.urls)),  # Add this line to include the viewsets


]
