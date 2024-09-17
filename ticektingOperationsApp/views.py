from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from decouple import config
from .dbUtils import get_connection
from .models import *
import json
import requests
import ast

# Create your views here.
@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def register(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not supported. Only POST requests are allowed.'}, status=405)

    if request.user.email not in ast.literal_eval(config("SUPER_USERS")):
        return JsonResponse({'error': 'Unauthorized access. Contact Admin.'}, status=403)

    try:
        data = json.loads(request.body)
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not username or not email or not password:
            return JsonResponse({'error': 'All fields (username, email, password) are required.'}, status=400)

        if User.objects.filter(username=username).exists():
            return JsonResponse({'error': 'Username already exists.'}, status=400)

        if User.objects.filter(email=email).exists():
            return JsonResponse({'error': 'Email already exists.'}, status=400)

        user = User.objects.create(
            username=username,
            email=email,
            password=make_password(password) 
        )

        return JsonResponse({
            'message': 'User registered successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            }
        }, status=201)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON format'}, status=400)

@csrf_exempt
def login(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            password = data.get('password')

            if not username or not password:
                return JsonResponse({'error': 'Username and password are required'}, status=400)

            user = authenticate(username=username, password=password)

            if user is not None:
                refresh = RefreshToken.for_user(user)

                return JsonResponse({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email
                    }
                }, status=200)
            else:
                return JsonResponse({'error': 'Invalid credentials'}, status=401)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format'}, status=400)
    else:
        return JsonResponse({'error': 'Only POST method is allowed'}, status=405)
    
def test(request):
    return JsonResponse({
        "message":"Hello World!"
    })

FRESHSERVICE_ACCOUNTS = [
    {
        "domain": "sq1-helpdesk.freshservice.com",
        "api_key": "WDVZWlVVUW4xcWFWbThSR0xmRA=="
    },
    {
        "domain": "sq1.freshservice.com",
        "api_key": "RElKcG5MOEFtcjBtNW53T2JySg=="
    }
]


@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def delete_all_tickets_freshservice(request):
    def delete_tickets_for_account(domain, api_key):
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {api_key}"
        }
        tickets_url = f"https://{domain}/api/v2/tickets"
        params = {
            "per_page": 100
        }

        try:
            while True:
                response = requests.get(tickets_url, headers=headers, params=params)
                if response.status_code != 200:
                    return {"error": f"Failed to fetch tickets from {domain}: {response.json()}"}, response.status_code

                tickets = response.json().get("tickets", [])
                if not tickets:
                    return {"message": f"No tickets found or all tickets have been deleted on {domain}."}, 200

                for ticket in tickets:
                    ticket_id = ticket.get("id")
                    delete_url = f"{tickets_url}/{ticket_id}"
                    delete_response = requests.delete(delete_url, headers=headers)

                    if delete_response.status_code == 204:
                        print(f"Ticket {ticket_id} deleted successfully on {domain}.")
                    else:
                        print(f"Failed to delete ticket {ticket_id} on {domain}: {delete_response.json()}")

                if "next_page" not in response.json():
                    break

            return {"message": f"All tickets have been deleted on {domain}."}, 200

        except Exception as e:
            return {"error": str(e)}, 500

    results = []
    for account in FRESHSERVICE_ACCOUNTS:
        domain = account["domain"]
        api_key = account["api_key"]
        result, status_code = delete_tickets_for_account(domain, api_key)
        results.append({"domain": domain, "result": result, "status_code": status_code})
        return JsonResponse({"message": "all freshservice tickets deleted"}, status=500)
    
    return JsonResponse({"messages": "success_messages"}, status=200)


@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def createTicketManuallyJira(request):
    from .scheduler import jira_call_create_ticket
    req = jira_call_create_ticket()
    return JsonResponse({
        "message":"hello world"
    })


@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def createTicketManuallyForFreshservice(request):
    from .scheduler import freshservice_call_create_ticket
    req = freshservice_call_create_ticket()
    return JsonResponse({
        "message":"hello world"
    })

@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def updateTicketManuallyForFreshService(request):
    from .scheduler import updateExploitsAndPatchesForFreshservice
    req = updateExploitsAndPatchesForFreshservice()
    return JsonResponse({
        "message":"hello world"
    })

JIRA_URL = config("JIRA_URL")
AUTH = (config("JIRA_USERNAME"), config("JIRA_PASSWORD"))

@csrf_exempt
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_jira_issues(request):
    if request.method == 'DELETE':
        try:
            response = requests.get("https://secqureone-team-r8i3piuv.atlassian.net/rest/api/3/search", auth=AUTH)
            if response.status_code != 200:
                return JsonResponse({'error': response.text}, status=response.status_code)

            issues = response.json().get('issues', [])
            responses = []
            for issue in issues:
                issue_key = issue['key']
                delete_response = requests.delete(f'{JIRA_URL}{issue_key}', auth=AUTH)
                if delete_response.status_code == 204:
                    responses.append({'key': issue_key, 'status': 'deleted'})
                else:
                    responses.append({'key': issue_key, 'status': 'error', 'message': delete_response.text})

            return JsonResponse(responses, safe=False)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def updateJiraPatchesAndExploits(request):
    from .scheduler import updateExploitsAndPatchesForJira
    req = updateExploitsAndPatchesForJira()
    return JsonResponse({
        "message":"sab changa si"
    })

# @csrf_exempt
# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def chechStatusForFreshServicesOrgs(request):
#     from .scheduler import changeVulnerabilityStatusForFreshService
#     req = changeVulnerabilityStatusForFreshService()
#     return JsonResponse(
#         {
#             "message":"sab changa si"
#         }
#     )

# @csrf_exempt
# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def checkStatusForJiraOrgs(request):
#     from .scheduler import changeVulnerabilityStatusForJira
#     req =changeVulnerabilityStatusForJira()
#     return JsonResponse(
#         {
#             "message":"sab changa si"
#         }
#     )

@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def cardCreateTrello(request):
    from .scheduler import createCardInTrello
    req =createCardInTrello()
    return JsonResponse(
        {
            "message":"sab changa si"
        }
    )

@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def updatatePatchesAndExploitsForTrello(request):
    from .scheduler import updateExploitsAndPatchesForTrello
    req =updateExploitsAndPatchesForTrello()
    return JsonResponse(
        {
            "message":"sab changa si"
        }
    )

