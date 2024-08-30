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
    ('freshservice', 'Freshservice')
]

class Vulnerabilities(models.Model):
    id = models.AutoField(primary_key=True)
    vulId = models.IntegerField()
    createdTicketId = models.CharField(max_length=255, default=None)
    organizationId = models.IntegerField(default=None)
    ticketServicePlatform = models.CharField(max_length=20, choices=TICKET_TYPE_CHOICES, default="")

class TicketingServiceDetails(models.Model):
    sq1VulId = models.IntegerField(null=True)
    ticketId = models.IntegerField(null=True)
    ticketServicePlatform = models.CharField(max_length=20, choices=TICKET_TYPE_CHOICES, default="", null=True)
    plannedStartDate = models.DateTimeField(null=True)
    plannedEffort = models.TimeField(null=True)
    subject = models.CharField(max_length=255, null=True)
    group_id = models.IntegerField(default=None, null=True)
    departmentId = models.IntegerField(default=None, null=True)
    category = models.CharField(max_length=255, default=None, null=True)
    subCategory = models.CharField(max_length=255, default=None, null=True)
    itemCategory = models.CharField(max_length=255, default=None, null=True)
    requesterId = models.IntegerField(null=True)
    responderId = models.IntegerField(null=True) 
    emailConfigId = models.CharField(max_length=255, default=None, null=True)
    fwdMails = models.TextField(default='[]', null=True)
    isEscalated = models.BooleanField(default=False, null=True)
    frDueBy = models.DateTimeField(null=True)
    createdAt = models.DateTimeField(null=True)
    updatedAt = models.DateTimeField(null=True)
    workSpaceId = models.IntegerField(null=True)
    requestedForId = models.BigIntegerField(validators=[validate_300_digit_max])
    toEmails = models.EmailField(null=True)
    type = models.CharField(max_length=255, null=True)
    description = models.TextField(null=True)
    descriptionHTML = models.TextField(null=True)
    majorIncidentType = models.CharField(max_length=255, null=True)
    businessImpact = models.CharField(max_length=255, null=True)
    numberOfCustomersImpacted = models.IntegerField(null=True)
    patchComplexity = models.CharField(max_length=20, choices=PATCH_COMPLEXITY_CHOICES, default="", null=True)
    patchUrl = models.CharField(max_length=255, null=True)
    patchOs = models.CharField(max_length=255, null=True)
    exploitsName = models.CharField(max_length=255, null=True)
    exploitsDescription = models.TextField(null=True)
    exploitsComplexity = models.CharField(max_length=20, choices=EXPLOITS_COMPLEXITY_CHOICES, default="", null=True)
    exploitsDependency = models.CharField(max_length=20, choices=EXPLOITS_DEPENDENCY_CHOICES, default="", null=True)
    tags = models.TextField(default='[]', null=True)
    tasksDependencyType = models.IntegerField(null=True)
    resolutionNotes = models.TextField(null=True)
    resolutionNotesHTML = models.TextField(null=True)
    attachments = models.TextField(default='[]', null=True)
    exploitsList = models.TextField(default='', null=True)
    patchesList = models.TextField(default='', null=True)

    def save(self, *args, **kwargs):
        self.fwdMails = json.dumps(self.fwdMails)
        self.tags = json.dumps(self.tags)
        self.attachments = json.dumps(self.attachments)
        super(TicketingServiceDetails, self).save(*args, **kwargs)

    def get_fwd_mails(self):
        return json.loads(self.fwdMails)

    def get_tags(self):
        return json.loads(self.tags)

    def get_attachments(self):
        return json.loads(self.attachments)
