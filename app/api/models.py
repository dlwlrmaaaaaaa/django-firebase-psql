from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
import uuid

class User(AbstractUser):
    # id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    ROLE_CHOICES = [
        ('citizen', 'Citizen'),
        ('worker', 'Worker'),
        ('department_admin', 'Department Admin'),
        ('superadmin', 'Super Admin'),
    ]
    role = models.CharField(max_length=50, choices=ROLE_CHOICES)
    contact_number = models.CharField(max_length=20, unique=True)
    department = models.CharField(max_length=100, null=True, blank=True)
    supervisor = models.ForeignKey('self', null=True, blank=True, on_delete=models.SET_NULL, related_name='subordinates') 
    address = models.TextField(null=True, blank=True)
    groups = models.ManyToManyField(Group, related_name='custom_user_groups')
    user_permissions = models.ManyToManyField(Permission, related_name='custom_user_permissions')
    otp = models.CharField(max_length=6, blank=True, null=True)
    is_email_verified = models.BooleanField(default=False)  # Set default to False
    ipv = models.CharField(max_length=20, unique=True, null=True)
    # first_name = models.CharField(max_length=100, null=True, blank=True)
    # middle_name = models.CharField(max_length=100, null=True, blank=True)
    # last_name = models.CharField(max_length=100, null=True, blank=True)
    # text_address = models.CharField(max_length=255, null=True, blank=True)
    # birthday = models.DateField(null=True, blank=True)
    # id_number = models.CharField(max_length=100, null=True, blank=True)
    # is_account_verified = models.BooleanField(default=False)
    # phofile_image_path = models.CharField(max_length=255, null=True, blank=True)
    # photo_image_path = models.CharField(max_length=255, null=True, blank=True)
    # id_selfie_image_path = models.CharField(max_length=255, null=True, blank=True)
    # id_picture_image_path = models.CharField(max_length=255, null=True, blank=True)


    def __str__(self):
        return self.username

class Report(models.Model):
    CATEGORY_CHOICES = [
        ('emergency', 'Emergency'),
        ('not emergency', 'Not Emergency'),
        ('maintenance', 'Maintenance'),
    ]
    report_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE) 
    image_path = models.CharField(max_length=255)
    assigned_by = models.CharField(max_length=50)
    assigned_by_department = models.CharField(max_length=100)
    type_of_report = models.CharField(max_length=100)
    report_description = models.CharField(max_length=255)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, null=True)
    latitude = models.FloatField(null=True)
    longitude = models.FloatField(null=True)
    upvote = models.IntegerField(default=0)
    downvote = models.IntegerField(default=0)
    report_date = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=50, default="Pending")

    def __str__(self):
        return self.type_of_report

class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

class Feedback(models.Model):
    report = models.ForeignKey(Report, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    comment = models.TextField()
    rating = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

class VerifyAccount(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='verification')
    first_name = models.CharField(max_length=100, null=True, blank=True)
    middle_name = models.CharField(max_length=100, null=True, blank=True)
    last_name = models.CharField(max_length=100, null=True, blank=True)
    text_address = models.CharField(max_length=255, null=True, blank=True)
    birthday = models.DateField(null=True, blank=True)
    id_number = models.CharField(max_length=100, null=True, blank=True)
    is_account_verified = models.BooleanField(default=False)
    profile_image_path = models.CharField(max_length=255, null=True, blank=True)
    photo_image_path = models.CharField(max_length=255, null=True, blank=True)
    id_selfie_image_path = models.CharField(max_length=255, null=True, blank=True)
    id_picture_image_path = models.CharField(max_length=255, null=True, blank=True)
