# Generated by Django 4.2.16 on 2024-11-25 23:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0012_report_location'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='score',
            field=models.IntegerField(null=True),
        ),
    ]