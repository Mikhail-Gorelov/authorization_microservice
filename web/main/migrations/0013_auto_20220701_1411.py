# Generated by Django 3.2.13 on 2022-07-01 11:11

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0012_alter_user_email'),
    ]

    operations = [
        migrations.RenameField(
            model_name='address',
            old_name='street_address_1',
            new_name='street_address',
        ),
        migrations.RemoveField(
            model_name='address',
            name='city_area',
        ),
        migrations.RemoveField(
            model_name='address',
            name='street_address_2',
        ),
    ]
