# Generated by Django 5.1.1 on 2024-10-29 08:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0007_merge_20241029_1117'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='role',
            field=models.CharField(choices=[('citizen', 'Citizen'), ('worker', 'Worker'), ('department admin', 'Department Admin'), ('superadmin', 'Super Admin')], max_length=50),
        ),
    ]
