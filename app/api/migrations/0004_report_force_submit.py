# Generated by Django 4.2.16 on 2024-12-02 07:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_report_report_count'),
    ]

    operations = [
        migrations.AddField(
            model_name='report',
            name='force_submit',
            field=models.BooleanField(default=False),
        ),
    ]