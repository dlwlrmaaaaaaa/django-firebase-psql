from django.apps import AppConfig
from django.db.utils import OperationalError, ProgrammingError

class ApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api'

    def ready(self):
        from .models import Department
        from .models import User
        try:
            default_departments = [
                "Fire Department",
                "Medical Department",
                "Police Department",
                "Street Maintenance",
                "Pothole Repair",
                "General Department"
            ]
            for dept_name in default_departments:
                Department.objects.get_or_create(name=dept_name)

            default_users =  {
                    "username": "admin",
                    "email": "admin@gmail.com",
                    "password": "admin",
                    "is_superuser": True,
                    "is_staff": True,
                    "is_active": True,
                    "is_email_verified": True,
                    "is_verified": True,
                    "role": "superadmin",
                }
            User.objects.get_or_create(username=default_users["username"], defaults=default_users)
        except (OperationalError, ProgrammingError):
            pass