from django.urls import path
from .views import *
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)

urlpatterns = [
    path('', test),
    path('create-user/', create_user, name='register'),
    path('login/', login, name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Freshservice
    path('create-ticket-manually-freshservice/', createTicketManuallyForFreshservice),
    path('update-ticket-manually-freshservice/', updateTicketManuallyForFreshService),
    path('delete-all-tickets-freshservice/', delete_all_tickets_freshservice, name='delete_all_tickets'),
    path('check-status-freshservice/', chechStatusForFreshServicesOrgs),

    # Jira
    path('create-ticket-manually-jira/', createTicketManuallyJira),
    path('update-jira-exploits-patches/', updateJiraPatchesAndExploits),
    path('delete_jira_issues/',delete_jira_issues),
    path('check-status-jira/', checkStatusForJiraOrgs),

    # Trello
    path('create_trello_card/',cardCreateTrello),
    path('update-trello-exploits-patches/',updatatePatchesAndExploitsForTrello),
    path('check-status-trello/', checkStatusForTrello),

    
    path('all-assets/', allAssets),
    path('get-asset-details/<int:id>/', getAssetDetails),
    # path('check-status-jira/', checkStatusForJiraOrgs),
]


 