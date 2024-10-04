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
            "per_page": 100,
            "page": 1 
        }

        try:
            total_deleted = 0
            while True:
                response = requests.get(tickets_url, headers=headers, params=params)
                if response.status_code != 200:
                    return {"error": f"Failed to fetch tickets from {domain}: {response.json()}"}, response.status_code

                tickets = response.json().get("tickets", [])
                if not tickets:
                    return {"message": f"No tickets found or all tickets have been deleted on {domain}. Total deleted: {total_deleted}"}, 200

                for ticket in tickets:
                    ticket_id = ticket.get("id")
                    delete_url = f"{tickets_url}/{ticket_id}"
                    delete_response = requests.delete(delete_url, headers=headers)

                    if delete_response.status_code == 204:
                        total_deleted += 1
                        print(f"Ticket {ticket_id} deleted successfully on {domain}.")
                    else:
                        print(f"Failed to delete ticket {ticket_id} on {domain}: {delete_response.json()}")

                if not response.json().get("next_page"):
                    break 

                params["page"] += 1

            return {"message": f"All tickets have been deleted on {domain}. Total deleted: {total_deleted}"}, 200

        except Exception as e:
            return {"error": str(e)}, 500

    def fetch_freshservice_accounts():
        connection = get_connection()
        cursor = connection.cursor(dictionary=True)
        query = "SELECT * FROM ticketing_tool WHERE type = 'freshservice'"
        cursor.execute(query)
        accounts = cursor.fetchall()
        cursor.close()
        return accounts

    accounts = fetch_freshservice_accounts()

    results = []
    for account in accounts:
        account_values = json.loads(account['values']) 
        domain = account_values.get("url").replace("https://", "")
        api_key = account_values.get("key")
        result, status_code = delete_tickets_for_account(domain, api_key)
        results.append({"domain": domain, "result": result, "status_code": status_code})

    return JsonResponse({"results": results}, status=200)


@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def createTicketManuallyJira(request):
    from .scheduler import jira_call_create_ticket
    req = jira_call_create_ticket()
    return JsonResponse(json.loads(req._container[0]))


@csrf_exempt
@api_view(['GET', 'DELETE'])
@permission_classes([IsAuthenticated])
def createTicketManuallyForFreshservice(request):
    from .scheduler import freshservice_call_create_ticket
    req = freshservice_call_create_ticket()
    return JsonResponse(json.loads(req._container[0]))

@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def updateTicketManuallyForFreshService(request):
    from .scheduler import updateExploitsAndPatchesForFreshservice
    req = updateExploitsAndPatchesForFreshservice()
    return JsonResponse(json.loads(req._container[0]))

@csrf_exempt
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_jira_issues(request):
    def delete_issues_for_account(jira_url, auth):
        try:
            total_deleted = 0
            start_at = 0
            max_results = 100  # Fetch 100 issues per page

            while True:
                search_url = f"{jira_url}/rest/api/3/search?startAt={start_at}&maxResults={max_results}"
                response = requests.get(search_url, auth=auth)

                if response.status_code != 200:
                    return {'error': response.text}, response.status_code

                issues = response.json().get('issues', [])
                if not issues:
                    break  # No more issues to delete

                for issue in issues:
                    issue_key = issue['key']
                    delete_response = requests.delete(f'{jira_url}/rest/api/3/issue/{issue_key}', auth=auth)

                    if delete_response.status_code == 204:
                        total_deleted += 1
                        print(f"Ticket {issue_key} deleted successfully.")
                    else:
                        print(f"Failed to delete ticket {issue_key}: {delete_response.text}")

                start_at += max_results  # Move to the next page of results

                if start_at >= response.json().get('total', 0):
                    break  # All issues have been processed

            return {'message': f"All tickets have been deleted. Total deleted: {total_deleted}"}, 200

        except Exception as e:
            return {'error': str(e)}, 500

    def fetch_jira_accounts():
        connection = get_connection()
        cursor = connection.cursor(dictionary=True)
        query = "SELECT * FROM ticketing_tool WHERE type = 'jira'"
        cursor.execute(query)
        accounts = cursor.fetchall()
        cursor.close()
        return accounts

    accounts = fetch_jira_accounts()

    results = []
    for account in accounts:
        account_values = json.loads(account['values'])
        jira_url = account_values.get("url")
        jira_username = account_values.get("username")
        jira_password = account_values.get("password")
        auth = (jira_username, jira_password)

        result, status_code = delete_issues_for_account(jira_url, auth)
        results.append({"jira_url": jira_url, "result": result, "status_code": status_code})

    return JsonResponse({"results": results}, status=200)


@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def updateJiraPatchesAndExploits(request):
    from .scheduler import updateExploitsAndPatchesForJira
    req = updateExploitsAndPatchesForJira()
    return JsonResponse(json.loads(req._container[0]))

@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def cardCreateTrello(request):
    from .scheduler import createCardInTrello
    req =createCardInTrello()
    return JsonResponse(
        json.loads(req._container[0])
    )

@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def updatatePatchesAndExploitsForTrello(request):
    from .scheduler import updateExploitsAndPatchesForTrello
    req =updateExploitsAndPatchesForTrello()
    return JsonResponse(
        json.loads(req._container[0])
    )

@csrf_exempt
# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
def chechStatusForFreshServicesOrgs(request):

    try:
        from .scheduler import changeVulnerabilityStatusForFreshService
        return changeVulnerabilityStatusForFreshService()
    
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
def checkStatusForJiraOrgs(request):
    from .scheduler import changeVulnerabilityStatusForJira
    response = changeVulnerabilityStatusForJira()

    # Check if the response is an instance of JsonResponse
    if isinstance(response, JsonResponse):
        return response

    return JsonResponse({"message": "Status check completed successfully."}, status=200)


@csrf_exempt
def checkStatusForTrello(request):
    from .scheduler import changeVulnerabilityStatusForTrello
    response = changeVulnerabilityStatusForTrello()
    return JsonResponse({})