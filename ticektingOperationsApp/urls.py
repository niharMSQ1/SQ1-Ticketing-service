from django.urls import path
from .views import *
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)

urlpatterns = [
    path('', test),
    path('login/', login, name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('delete-all-tickets-freshservice/', delete_all_tickets_freshservice, name='delete_all_tickets'),
    path('create-ticket-manually-freshservice/', createTicketManuallyForFreshservice),
    path('create-ticket-manually-jira/', createTicketManuallyJira),
    path('update-ticket-manually-freshservice/', updateTicketManuallyForFreshService),
    path('delete_jira_issues/',delete_jira_issues),
    path('update-jira-exploits-patches/', updateJiraPatchesAndExploits),
    path('check-status-freshservice/', chechStatusForFreshServicesOrgs),
    path('check-status-jira/', checkStatusForJiraOrgs),
    path('create_trello_card/',cardCreateTrello),
    path('update-trello-exploits-patches/',updatatePatchesAndExploitsForTrello),
    path('register/', register, name='register'),
    path('start-scheduler/', scheduler_view, name='start_scheduler'),
]


 