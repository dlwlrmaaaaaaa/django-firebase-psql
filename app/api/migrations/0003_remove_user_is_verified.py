# Generated by Django 4.2.16 on 2024-10-27 09:06

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0002_user_violation'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='is_verified',
        ),
    ]