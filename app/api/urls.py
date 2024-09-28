from django.urls import path
from .views import MyTokenObtainPairView, SomeView, CitizenRegitsration, DepartmentRegistration, WorkerRegistration, ReportView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('token/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'), ## This is login and generated token
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'), ## this is refresh token where you will get another access token
    path('superadmin-only/', SomeView.as_view(), name='protected_superadmin'),## this is for test auth

    ### This is for Registration
    path('citizen/registration/', CitizenRegitsration.as_view(), name='citizen_registration'),
    path('department_admin/registration/', DepartmentRegistration.as_view(), name='admin_registration'),
    path('worker/registration/', WorkerRegistration.as_view(), name='worker_registration'),

    ### For reports
    path('create-report/', ReportView.as_view(), name='create-report')
]
