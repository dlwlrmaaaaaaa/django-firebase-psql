from django.apps import AppConfig
from django.db.utils import OperationalError, ProgrammingError
from django.core.management import call_command
from django.db.models.signals import post_migrate
from django.contrib.auth import get_user_model

class ApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api'

    def ready(self):
        from .models import Department  # Import here to avoid circular dependencies

        def initialize_data(sender, **kwargs):
            try:
                # Create default departments
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

                # Create superuser
                User = get_user_model()
                admin_data = {
                    "username": "admin",
                    "email": "admin@gmail.com",
                    "is_superuser": True,
                    "is_staff": True,
                    "is_active": True,
                    "is_email_verified": True,
                    "is_verified": True,
                    "role": "superadmin",
                }

          

                user, created = User.objects.get_or_create(username=admin_data["username"], defaults=admin_data)

                if created:
                    user.set_password('admin')  # Use an env variable instead
                    user.save()
                    print(f"Superuser {user.username} created.")
                else:
                    print(f"Superuser {user.username} already exists.")

            except (OperationalError, ProgrammingError):
                pass

        # Connect to post_migrate signal
        post_migrate.connect(initialize_data, sender=self)