import ast
import base64
import json
import requests

from decouple import config
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken

from .dbUtils import get_connection
from .helper import get_user_permission_list
from .models import *


# Create your views here.
'''sample API example'''

# @csrf_exempt
# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def viewName(request):
#     checkUser = (User.objects.filter(username = request.user.username)).exists()
#     if checkUser:
#         user = (User.objects.get(username = request.user.username))
#         permissionList = get_user_permission_list(user)
#         if (request.resolver_match.view_name).split('.')[-1] in list(permissionList) and permissionList.get((request.resolver_match.view_name).split('.')[-1]) == True or request.user.is_superuser == True: 
#             print()
#             '''
#             Write your code here
#             '''

#         else:
#             return JsonResponse({
#                 "message":"Acces denied"
#             })
#     else:
#         return JsonResponse({
#             "message":"User not found"
#         })

@csrf_exempt
@api_view(['POST'])
def create_user(request):
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Permission denied. Contact Admin.'}, status=403)
    
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not supported. Only POST requests are allowed.'}, status=405)

    try:
        data = json.loads(request.body)
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        apiPermissions = {
            "createTicketManuallyForFreshservice": True,
            "delete_all_tickets_freshservice": False,
            "chechStatusForFreshServicesOrgs": False,
            "createTicketManuallyJira": False,
            "updateJiraPatchesAndExploits": True,
            "delete_jira_issues": False,
            "checkStatusForJiraOrgs": True,
            "cardCreateTrello": True,
            "updatatePatchesAndExploitsForTrello": True,
            "checkStatusForTrello": True
        }


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

        givePermissions = UserApiMap(user=user ,apiList=apiPermissions)
        givePermissions.save()



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
                deleteToken = (OutstandingToken.objects.filter(user=user)).delete()
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
    checkUser = (User.objects.filter(username = request.user.username)).exists()
    if checkUser:
        user = (User.objects.get(username = request.user.username))
        permissionList = get_user_permission_list(user)
        if (request.resolver_match.view_name).split('.')[-1] in list(permissionList) and permissionList.get((request.resolver_match.view_name).split('.')[-1]) == True or request.user.is_superuser == True: 
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
                api_key =base64.b64encode(bytes(account_values.get("key"), "utf-8")).decode("utf-8", "ignore")
                result, status_code = delete_tickets_for_account(domain, api_key)
                results.append({"domain": domain, "result": result, "status_code": status_code})

            return JsonResponse({"results": results}, status=200)
        else:
            return JsonResponse({
                "message":"Acces denied"
            })
    else:
        return JsonResponse({
            "message":"User not found"
        })


@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def createTicketManuallyJira(request):
    checkUser = (User.objects.filter(username = request.user.username)).exists()
    if checkUser:
        user = (User.objects.get(username = request.user.username))
        permissionList = get_user_permission_list(user)
        if (request.resolver_match.view_name).split('.')[-1] in list(permissionList) and permissionList.get((request.resolver_match.view_name).split('.')[-1]) == True or request.user.is_superuser == True: 
            from .scheduler import jira_call_create_ticket
            req = jira_call_create_ticket()
            return JsonResponse(json.loads(req._container[0]))
        
        else:
            return JsonResponse({
                "message":"Acces denied"
            })
    else:
        return JsonResponse({
            "message":"User not found"
        })

@csrf_exempt
@api_view(['GET', 'DELETE'])
@permission_classes([IsAuthenticated])
def createTicketManuallyForFreshservice(request):
    checkUser = (User.objects.filter(username = request.user.username)).exists()
    if checkUser:
        user = (User.objects.get(username = request.user.username))
        permissionList = get_user_permission_list(user)
        if (request.resolver_match.view_name).split('.')[-1] in list(permissionList) and permissionList.get((request.resolver_match.view_name).split('.')[-1]) == True or request.user.is_superuser == True: 
            from .scheduler import freshservice_call_create_ticket
            req = freshservice_call_create_ticket()
            return JsonResponse(json.loads(req._container[0]))
        else:
            return JsonResponse({
                "message":"Acces denied"
            })
    else:
        return JsonResponse({
            "message":"User not found"
        })

@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def updateTicketManuallyForFreshService(request):
    checkUser = (User.objects.filter(username = request.user.username)).exists()
    if checkUser:
        user = (User.objects.get(username = request.user.username))
        permissionList = get_user_permission_list(user)
        if (request.resolver_match.view_name).split('.')[-1] in list(permissionList) and permissionList.get((request.resolver_match.view_name).split('.')[-1]) == True or request.user.is_superuser == True: 
            from .scheduler import updateExploitsAndPatchesForFreshservice
            req = updateExploitsAndPatchesForFreshservice()
            return JsonResponse(json.loads(req._container[0]))
        else:
            return JsonResponse({
                "message":"Acces denied"
            })
    else:
        return JsonResponse({
            "message":"User not found"
        })

@csrf_exempt
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_jira_issues(request):
    checkUser = (User.objects.filter(username = request.user.username)).exists()
    if checkUser:
        user = (User.objects.get(username = request.user.username))
        permissionList = get_user_permission_list(user)
        if (request.resolver_match.view_name).split('.')[-1] in list(permissionList) and permissionList.get((request.resolver_match.view_name).split('.')[-1]) == True or request.user.is_superuser == True: 
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
        else:
            return JsonResponse({
                "message":"Acces denied"
            })
    else:
        return JsonResponse({
            "message":"User not found"
        })


@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def updateJiraPatchesAndExploits(request):
    checkUser = (User.objects.filter(username = request.user.username)).exists()
    if checkUser:
        user = (User.objects.get(username = request.user.username))
        permissionList = get_user_permission_list(user)
        if (request.resolver_match.view_name).split('.')[-1] in list(permissionList) and permissionList.get((request.resolver_match.view_name).split('.')[-1]) == True or request.user.is_superuser == True:
            from .scheduler import updateExploitsAndPatchesForJira
            req = updateExploitsAndPatchesForJira()
            return JsonResponse(json.loads(req._container[0]))
        else:
            return JsonResponse({
                "message":"Acces denied"
            })
    else:
        return JsonResponse({
            "message":"User not found"
        })

@csrf_exempt
@api_view(['GET', 'DELETE'])
@permission_classes([IsAuthenticated])
def cardCreateTrello(request):
    checkUser = (User.objects.filter(username = request.user.username)).exists()
    if checkUser:
        user = (User.objects.get(username = request.user.username))
        permissionList = get_user_permission_list(user)
        if (request.resolver_match.view_name).split('.')[-1] in list(permissionList) and permissionList.get((request.resolver_match.view_name).split('.')[-1]) == True or request.user.is_superuser == True: 
            from .scheduler import createCardInTrello
            req =createCardInTrello()
            return JsonResponse(
                json.loads(req._container[0])
            )
        else:
            return JsonResponse({
                "message":"Acces denied"
            })
    else:
        return JsonResponse({
            "message":"User not found"
        })

@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def updatatePatchesAndExploitsForTrello(request):
    checkUser = (User.objects.filter(username = request.user.username)).exists()
    if checkUser:
        user = (User.objects.get(username = request.user.username))
        permissionList = get_user_permission_list(user)
        if (request.resolver_match.view_name).split('.')[-1] in list(permissionList) and permissionList.get((request.resolver_match.view_name).split('.')[-1]) == True or request.user.is_superuser == True: 
            from .scheduler import updateExploitsAndPatchesForTrello
            req =updateExploitsAndPatchesForTrello()
            return JsonResponse(
                json.loads(req._container[0])
            )
        else:
            return JsonResponse({
                "message":"Acces denied"
            })
    else:
        return JsonResponse({
            "message":"User not found"
        })

@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def chechStatusForFreshServicesOrgs(request):
    checkUser = (User.objects.filter(username = request.user.username)).exists()
    if checkUser:
        user = (User.objects.get(username = request.user.username))
        permissionList = get_user_permission_list(user)
        if (request.resolver_match.view_name).split('.')[-1] in list(permissionList) and permissionList.get((request.resolver_match.view_name).split('.')[-1]) == True or request.user.is_superuser == True: 

            try:
                from .scheduler import changeVulnerabilityStatusForFreshService
                return changeVulnerabilityStatusForFreshService()
            
            except Exception as e:
                return JsonResponse({"error": str(e)}, status=500)
        else:
            return JsonResponse({
                "message":"Acces denied"
            })
    else:
        return JsonResponse({
            "message":"User not found"
        })

@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def checkStatusForJiraOrgs(request):
    checkUser = (User.objects.filter(username = request.user.username)).exists()
    if checkUser:
        user = (User.objects.get(username = request.user.username))
        permissionList = get_user_permission_list(user)
        if (request.resolver_match.view_name).split('.')[-1] in list(permissionList) and permissionList.get((request.resolver_match.view_name).split('.')[-1]) == True or request.user.is_superuser == True: 
            from .scheduler import changeVulnerabilityStatusForJira
            response = changeVulnerabilityStatusForJira()

            if isinstance(response, JsonResponse):
                return response

            return JsonResponse({"message": "Status check completed successfully."}, status=200)
        else:
            return JsonResponse({
                "message":"Acces denied"
            })
    else:
        return JsonResponse({
            "message":"User not found"
        })


@csrf_exempt
def checkStatusForTrello(request):
    checkUser = (User.objects.filter(username = request.user.username)).exists()
    if checkUser:
        user = (User.objects.get(username = request.user.username))
        permissionList = get_user_permission_list(user)
        if (request.resolver_match.view_name).split('.')[-1] in list(permissionList) and permissionList.get((request.resolver_match.view_name).split('.')[-1]) == True or request.user.is_superuser == True:
            from .scheduler import changeVulnerabilityStatusForTrello
            response = changeVulnerabilityStatusForTrello()
            return JsonResponse({})
        else:
            return JsonResponse({
                "message":"Acces denied"
            })
    else:
        return JsonResponse({
            "message":"User not found"
        })

@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def allAssets(request):
    checkUser = User.objects.filter(username=request.user.username).exists()
    if checkUser:
        user = User.objects.get(username=request.user.username)
        permissionList = get_user_permission_list(user)
        
        view_name = request.resolver_match.view_name.split('.')[-1]

        if view_name in list(permissionList) and permissionList.get(view_name) == True or request.user.is_superuser:
            connection = get_connection()
            if not connection or not connection.is_connected():
                return JsonResponse({"error": "Failed to connect to the database"}, status=500)
            
            try:
                with connection.cursor(dictionary=True) as cursor:
                    cursor.execute("SELECT * FROM workstations;")
                    workstations = cursor.fetchall()

                    cursor.execute("SELECT * FROM servers;")
                    servers = cursor.fetchall()
                
                return JsonResponse({
                    "workstations": workstations,
                    "servers": servers
                }, status=200)

            except Exception as e:
                return JsonResponse({"error": str(e)}, status=500)

        else:
            return JsonResponse({"message": "Access denied"}, status=403)
    
    else:
        return JsonResponse({"message": "User not found"}, status=404)
    
@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def getAssetDetails(request, id):
    checkUser = (User.objects.filter(username=request.user.username)).exists()

    if checkUser:
        user = (User.objects.get(username=request.user.username))
        permissionList = get_user_permission_list(user)

        if (request.resolver_match.view_name).split('.')[-1] in list(permissionList) and permissionList.get(
                (request.resolver_match.view_name).split('.')[-1]) == True or request.user.is_superuser == True:
            connection = get_connection()

            if not connection or not connection.is_connected():
                return JsonResponse({"error": "Failed to connect to the database"}, status=500)

            try:
                with connection.cursor(dictionary=True) as cursor:
                    cursor.execute("SELECT * FROM assetables WHERE id = %s", (id,))
                    assetables = cursor.fetchall()
                    asset_id = assetables[0]['assetable_id']

                    if assetables[0]['assetable_type'] == 'App\\Models\\Servers':
                        cursor.execute("SELECT * FROM servers WHERE id = %s", (asset_id,))
                        serverDetails = cursor.fetchall()
                        return JsonResponse({
                            "Server Details": serverDetails,
                        }, status=200)

                    elif assetables[0]['assetable_type'] == 'App\\Models\\Workstations':
                        cursor.execute("SELECT * FROM servers WHERE id = %s", (asset_id,))
                        workstationDetails = cursor.fetchall()
                        return JsonResponse({
                            "Workstation Details": workstationDetails,
                        }, status=200)

            except Exception as e:
                return JsonResponse({"error": str(e)}, status=500)

        else:
            return JsonResponse({
                "message": "Access denied"
            })

    else:
        return JsonResponse({
            "message": "User not found"
        })
    
@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def retire_assets_list(request):
    user = get_object_or_404(User, username=request.user.username)
    permission_list = get_user_permission_list(user)

    view_name = request.resolver_match.view_name.split('.')[-1]
    has_permission = permission_list.get(view_name) is True or request.user.is_superuser

    if has_permission:
        try:
            connection = get_connection()
            with connection.cursor() as cursor: # Need to verify the query
                cursor.execute("""
                    SELECT assetable_id 
                    FROM assetables 
                    WHERE assetable_type = 'App\\Models\\Workstations' 
                    AND assetable_id IN (
                        SELECT id 
                        FROM workstations 
                        WHERE deleted_at IS NULL
                    )
                    UNION
                    SELECT assetable_id 
                    FROM assetables 
                    WHERE assetable_type = 'App\\Models\\Servers' 
                    AND assetable_id IN (
                        SELECT id 
                        FROM servers 
                        WHERE deleted_at IS NULL
                    );
                """)

                results = cursor.fetchall()
                assetable_ids = [{'assetable_id': row[0]} for row in results]

            return JsonResponse({
                "Retire asset lists": assetable_ids,
            }, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({
        "message": "Access denied"
    }, status=403)

@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def listVulnerabilities(request):
    user = get_object_or_404(User, username=request.user.username)
    permission_list = get_user_permission_list(user)

    view_name = request.resolver_match.view_name.split('.')[-1]
    has_permission = permission_list.get(view_name) is True or request.user.is_superuser

    if has_permission:
        try:
            connection = get_connection()
            with connection.cursor() as cursor: # Need to verify the query
                cursor.execute("SELECT * FROM vulnerabilities")

                results = cursor.fetchall()

            return JsonResponse({
                "Vulnerabilities lists": results,
            }, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({
        "message": "Access denied"
    }, status=403)

@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def listCriticalVulnerabilities(request):
    user = get_object_or_404(User, username=request.user.username)
    permission_list = get_user_permission_list(user)

    view_name = request.resolver_match.view_name.split('.')[-1]
    has_permission = permission_list.get(view_name) is True or request.user.is_superuser

    if has_permission:
        try:
            connection = get_connection()
            with connection.cursor() as cursor: # Need to verify the query
                cursor.execute("SELECT * FROM vulnerabilities where risk >= 7")

                results = cursor.fetchall()

            return JsonResponse({
                "Critical Vulnerabilities lists": results,
            }, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({
        "message": "Access denied"
    }, status=403)

@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def getVulnerabilityDetails(request,id):
    user = get_object_or_404(User, username=request.user.username)
    permission_list = get_user_permission_list(user)

    view_name = request.resolver_match.view_name.split('.')[-1]
    has_permission = permission_list.get(view_name) is True or request.user.is_superuser

    if has_permission:
        try:
            connection = get_connection()
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM vulnerabilities WHERE id = %s", (id,))

                results = cursor.fetchall()

            return JsonResponse({
                "Vulnerabilities details": results,
            }, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({
        "message": "Access denied"
    }, status=403)

@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def getVulnerabilityExploits(request,id):
    user = get_object_or_404(User, username=request.user.username)
    permission_list = get_user_permission_list(user)

    view_name = request.resolver_match.view_name.split('.')[-1]
    has_permission = permission_list.get(view_name) is True or request.user.is_superuser

    if has_permission:
        try:
            connection = get_connection()
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM exploits WHERE vul_id  = %s", (id,))

                results = cursor.fetchall()

            return JsonResponse({
                "Exploits lists": results,
            }, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({
        "message": "Access denied"
    }, status=403)

@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def getVulnerabilityPatches(request,id):
    user = get_object_or_404(User, username=request.user.username)
    permission_list = get_user_permission_list(user)

    view_name = request.resolver_match.view_name.split('.')[-1]
    has_permission = permission_list.get(view_name) is True or request.user.is_superuser

    if has_permission:
        try:
            connection = get_connection()
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM patch WHERE vul_id  = %s", (id,))

                results = cursor.fetchall()

            return JsonResponse({
                "Patche(s) lists": results,
            }, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({
        "message": "Access denied"
    }, status=403)