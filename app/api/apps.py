from django.apps import AppConfig
from django.db.utils import OperationalError, ProgrammingError

class ApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api'

    def ready(self):
        from .models import Department
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
        except (OperationalError, ProgrammingError):
            pass