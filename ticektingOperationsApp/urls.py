from django.urls import path
from .views import *

urlpatterns = [
    path('', test),
    path('delete-all-tickets-freshservice/', delete_all_tickets_freshservice, name='delete_all_tickets'),
    path('create-ticket-manually-freshservice/', createTicketManuallyForFreshservice),
    path('create-ticket-manually-jira/', createTicketManuallyJira),
    path('update-ticket-manually-freshservice/', updateTicketManuallyForFreshService),
    path('delete_jira_issues/',delete_jira_issues),
    path('update-jira-exploits-patches/', updateJiraPatchesAndExploits),
    path('check-status-freshservice/', chechStatusForFreshServicesOrgs),
    path('check-status-jira/', checkStatusForJiraOrgs),
    path('create_trello_card/',cardCreateTrello),
    path('update-trello-exploits-patches/',updatatePatchesAndExploitsForTrello)
]


 