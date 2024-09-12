from .models import  TicketingServiceDetails, TICKET_TYPE_CHOICES, TICKET_REFERENCE_CHOICES

# def save_vulnerability(vul_id, organization_id, ticket_id):
#     Vulnerabilities.objects.create(
#         vulId=vul_id,
#         cVulId = [key for key, value in TICKET_REFERENCE_CHOICES if value == 'Freshservice'][0] + "-" +str(vul_id),
#         ticketServicePlatform=[key for key, value in TICKET_TYPE_CHOICES if value == 'Freshservice'][0],
#         organizationId=organization_id,
#         createdTicketId=ticket_id
#     )

def save_ticket_details(ticket_data,vul_id,exploitIdList,patchesIdList,organization_id):
    TicketingServiceDetails.objects.create(
        exploitsList = exploitIdList,
        patchesList = patchesIdList,
        organizationId = organization_id,
        sq1VulId = vul_id,
        ticketId=ticket_data.get("id", None),
        cVulId = [key for key, value in TICKET_REFERENCE_CHOICES if value == 'Freshservice'][0] + "-" +str(vul_id), 
        ticketServicePlatform=[key for key, value in TICKET_TYPE_CHOICES if value == 'Freshservice'][0],
    )
