# Generated by Django 5.1.1 on 2024-10-16 13:54

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0007_report_downvote'),
    ]

    operations = [
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
