# Generated by Django 5.1 on 2024-10-23 08:33

import django.contrib.auth.models
import django.contrib.auth.validators
import django.db.models.deletion
import django.utils.timezone
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('username', models.CharField(error_messages={'unique': 'A user with that username already exists.'}, help_text='Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.', max_length=150, unique=True, validators=[django.contrib.auth.validators.UnicodeUsernameValidator()], verbose_name='username')),
                ('first_name', models.CharField(blank=True, max_length=150, verbose_name='first name')),
                ('last_name', models.CharField(blank=True, max_length=150, verbose_name='last name')),
                ('email', models.EmailField(blank=True, max_length=254, verbose_name='email address')),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this user should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('role', models.CharField(choices=[('citizen', 'Citizen'), ('worker', 'Worker'), ('department_admin', 'Department Admin'), ('superadmin', 'Super Admin')], max_length=50)),
                ('contact_number', models.CharField(max_length=20, unique=True)),
                ('department', models.CharField(blank=True, max_length=100, null=True)),
                ('address', models.TextField(blank=True, null=True)),
                ('otp', models.CharField(blank=True, max_length=6, null=True)),
                ('is_email_verified', models.BooleanField(default=False)),
                ('ipv', models.CharField(max_length=20, null=True, unique=True)),
                ('is_verified', models.BooleanField(default=False)),
                ('account_status', models.CharField(choices=[('active', 'Active'), ('suspended', 'Suspended'), ('blocked', 'Blocked')], default='active', max_length=10)),
                ('groups', models.ManyToManyField(related_name='custom_user_groups', to='auth.group')),
                ('supervisor', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='subordinates', to=settings.AUTH_USER_MODEL)),
                ('user_permissions', models.ManyToManyField(related_name='custom_user_permissions', to='auth.permission')),
            ],
            options={
                'verbose_name': 'user',
                'verbose_name_plural': 'users',
                'abstract': False,
            },
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.CreateModel(
            name='Notification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('message', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('is_read', models.BooleanField(default=False)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Report',
            fields=[
                ('report_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('image_path', models.CharField(max_length=255)),
                ('assigned_by', models.CharField(max_length=50)),
                ('assigned_by_department', models.CharField(max_length=100)),
                ('type_of_report', models.CharField(max_length=100)),
                ('report_description', models.CharField(max_length=255)),
                ('is_emergency', models.CharField(choices=[('emergency', 'Emergency'), ('not emergency', 'Not Emergency'), ('maintenance', 'Maintenance')], max_length=20, null=True)),
                ('latitude', models.FloatField(null=True)),
                ('longitude', models.FloatField(null=True)),
                ('upvote', models.IntegerField(default=0)),
                ('downvote', models.IntegerField(default=0)),
                ('report_date', models.DateTimeField(auto_now=True)),
                ('status', models.CharField(default='Pending', max_length=50)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Feedback',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('comment', models.TextField()),
                ('rating', models.IntegerField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('report', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.report')),
            ],
        ),
        migrations.CreateModel(
            name='VerifyAccount',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('first_name', models.CharField(blank=True, max_length=100, null=True)),
                ('middle_name', models.CharField(blank=True, max_length=100, null=True)),
                ('last_name', models.CharField(blank=True, max_length=100, null=True)),
                ('text_address', models.CharField(blank=True, max_length=255, null=True)),
                ('birthday', models.DateField(blank=True, null=True)),
                ('id_number', models.CharField(blank=True, max_length=100, null=True)),
                ('is_account_verified', models.BooleanField(default=False)),
                ('profile_image_path', models.CharField(blank=True, max_length=255, null=True)),
                ('photo_image_path', models.CharField(blank=True, max_length=255, null=True)),
                ('id_selfie_image_path', models.CharField(blank=True, max_length=255, null=True)),
                ('id_picture_image_path', models.CharField(blank=True, max_length=255, null=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='verification', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
