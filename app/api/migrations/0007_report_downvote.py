# Generated by Django 4.2.16 on 2024-10-09 07:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0006_alter_report_category'),
    ]

    operations = [
        migrations.AddField(
            model_name='report',
            name='downvote',
            field=models.IntegerField(default=0),
        ),
    ]
