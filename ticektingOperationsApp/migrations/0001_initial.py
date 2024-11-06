# Generated by Django 5.1 on 2024-11-06 08:52

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='TicketingServiceDetails',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sq1VulId', models.IntegerField(null=True)),
                ('cVulId', models.CharField(max_length=255)),
                ('organizationId', models.IntegerField(default=None)),
                ('ticketId', models.IntegerField(null=True)),
                ('ticketIdIfString', models.CharField(max_length=255, null=True)),
                ('ticketServicePlatform', models.CharField(choices=[('jira', 'JIRA'), ('freshservice', 'Freshservice'), ('trello', 'Trello')], default='', max_length=20, null=True)),
                ('exploitsList', models.TextField(default='', null=True)),
                ('patchesList', models.TextField(default='', null=True)),
                ('isActive', models.BooleanField(default=True)),
            ],
        ),
        migrations.CreateModel(
            name='UserApiMap',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('apiList', models.JSONField(default=list)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
