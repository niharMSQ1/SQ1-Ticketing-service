from django.core.exceptions import ValidationError
from django.db import models
import json


def validate_300_digit_max(value):
    if len(str(value)) > 30:
        raise ValidationError('Value cannot exceed 30 digits.')

PATCH_COMPLEXITY_CHOICES = [
    ('low', 'Low'),
    ('medium', 'Medium'),
    ('high', 'High'),
    ('critical', 'Critical')
]

EXPLOITS_COMPLEXITY_CHOICES = [
    ('low', 'Low'),
    ('medium', 'Medium'),
    ('high', 'High'),
    ('critical', 'Critical')
]

EXPLOITS_DEPENDENCY_CHOICES = [
    ('yes', 'Yes'),
    ('no', 'No')
]

TICKET_TYPE_CHOICES = [
    ('jira', 'JIRA'),
    ('freshservice', 'Freshservice'),
    ('trello', 'Trello')
]

TICKET_REFERENCE_CHOICES = [
    ('JR', 'JIRA'),
    ('FR', 'Freshservice'),
    ('TR', 'Trello')
]

class Vulnerabilities(models.Model):
    id = models.AutoField(primary_key=True)
    vulId = models.IntegerField()
    cVulId =models.CharField(max_length=255)
    createdTicketId = models.CharField(max_length=255, default=None)
    organizationId = models.IntegerField(default=None)
    ticketServicePlatform = models.CharField(max_length=20, choices=TICKET_TYPE_CHOICES, default="")

class TicketingServiceDetails(models.Model):
    sq1VulId = models.IntegerField(null=True)
    cVulId =models.CharField(max_length=255)
    ticketId = models.IntegerField(null=True)
    ticketIdIfString = models.CharField(max_length=255,null=True)
    ticketServicePlatform = models.CharField(max_length=20, choices=TICKET_TYPE_CHOICES, default="", null=True)
    exploitsList = models.TextField(default='', null=True)
    patchesList = models.TextField(default='', null=True)
    isActive = models.BooleanField(default=True)

    def save(self, *args, **kwargs):
        super(TicketingServiceDetails, self).save(*args, **kwargs)

    def get_fwd_mails(self):
        return json.loads(self.fwdMails)

    def get_tags(self):
        return json.loads(self.tags)

    def get_attachments(self):
        return json.loads(self.attachments)
