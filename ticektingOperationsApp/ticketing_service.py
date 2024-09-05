from .models import Vulnerabilities, TicketingServiceDetails, TICKET_TYPE_CHOICES, TICKET_REFERENCE_CHOICES

def save_vulnerability(vul_id, organization_id, ticket_id):
    Vulnerabilities.objects.create(
        vulId=vul_id,
        cVulId = [key for key, value in TICKET_REFERENCE_CHOICES if value == 'Freshservice'][0] + "-" +str(vul_id),
        ticketServicePlatform=[key for key, value in TICKET_TYPE_CHOICES if value == 'Freshservice'][0],
        organizationId=organization_id,
        createdTicketId=ticket_id
    )

def save_ticket_details(ticket_data,vul_id,exploitIdList,patchesIdList):
    TicketingServiceDetails.objects.create(
        exploitsList = exploitIdList,
        patchesList = patchesIdList,
        sq1VulId = vul_id,
        ticketId=ticket_data.get("id", None),
        cVulId = [key for key, value in TICKET_REFERENCE_CHOICES if value == 'Freshservice'][0] + "-" +str(vul_id), 
        ticketServicePlatform=[key for key, value in TICKET_TYPE_CHOICES if value == 'Freshservice'][0],
        plannedStartDate=ticket_data.get("planned_start_date") or None,
        plannedEffort=ticket_data.get("planned_end_date") or None,
        subject=ticket_data.get("subject", ""),
        group_id=ticket_data.get("group_id") or None,
        departmentId=ticket_data.get("department_id") or None,
        category=ticket_data.get("category") or None,
        subCategory=ticket_data.get("sub_category") or None,
        itemCategory=ticket_data.get("item_category") or None,
        requesterId=ticket_data.get("requestor_id") or None,
        responderId=ticket_data.get("responder_id") or None,
        emailConfigId=ticket_data.get("email_config_id") or None,
        fwdMails=ticket_data.get("fwd_mails", []),
        isEscalated=ticket_data.get("is_escalated", False),
        frDueBy=ticket_data.get("fr_due_by") or None,
        createdAt=ticket_data.get("created_at") or None,
        updatedAt=ticket_data.get("updated_at") or None,
        workSpaceId=ticket_data.get("workspace_id") or None,
        requestedForId=ticket_data.get("requested_for_id") or None,
        toEmails=ticket_data.get("to_emails", None),
        type=ticket_data.get("type", "Incident"),
        description=ticket_data.get("description_text", ""),
        descriptionHTML=ticket_data.get("description", ""),
        majorIncidentType=ticket_data.get("major_incident_type") or None,
        businessImpact=ticket_data.get("business_impact") or None,
        numberOfCustomersImpacted=ticket_data.get("no_of_customers_impacted") or None,
        patchComplexity=ticket_data.get("patchcomplexity") or None,
        patchUrl=ticket_data.get("patchurl", ""),
        patchOs=ticket_data.get("patchos", ""),
        exploitsName=ticket_data.get("exploitsname", ""),
        exploitsDescription=ticket_data.get("exploitsdescription", ""),
        exploitsComplexity=ticket_data.get("exploitscomplexity") or None,
        exploitsDependency=ticket_data.get("exploitsdependency") or None,
        tags=ticket_data.get("tags", []),
        tasksDependencyType=ticket_data.get("tasks_dependency_type") or None,
        resolutionNotes=ticket_data.get("resolution_notes") or None,
        resolutionNotesHTML=ticket_data.get("resolution_notes_html") or None,
        attachments=ticket_data.get("attachments", [])
    )
