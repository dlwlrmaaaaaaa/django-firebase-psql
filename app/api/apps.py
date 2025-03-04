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
                "General Department",
                
            ]
            for dept_name in default_departments:
                Department.objects.get_or_create(name=dept_name)

            default_users = {
                "username": "admin",
                "email": "admin@gmail.com",
                "is_superuser": True,
                "is_staff": True,
                "is_active": True,
                "is_email_verified": True,
                "is_verified": True,
                "role": "superadmin",
            }

            # Create or get the user
            user, created = User.objects.get_or_create(username=default_users["username"], defaults=default_users)

            # Set the password after creation or fetching the user
            user.set_password('your_password_here')  # Replace with the desired password

            # Save the user to update the password
            user.save()

            # Optionally, print if the user was created or updated
            if created:
                print(f"User {user.username} was created.")
            else:
                print(f"User {user.username} already exists.")
        except (OperationalError, ProgrammingError):
            pass