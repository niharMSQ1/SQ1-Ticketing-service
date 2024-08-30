from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from decouple import config

from .dbUtils import get_connection
from .models import Vulnerabilities

import json
import requests

# Create your views here.
def test(request):
    return JsonResponse({
        "message":"Hello World!"
    })

FRESHSERVICE_ACCOUNTS = [
    {
        "domain": "sq1vinay.freshservice.com",
        "api_key": "eE4xcmdQMFlobkZyV1JZdmV2a1Q=	"
    },
    {
        "domain": "sq1.freshservice.com",
        "api_key": "RElKcG5MOEFtcjBtNW53T2JySg=="
    }
]

@csrf_exempt
def delete_all_tickets(request):
    def delete_tickets_for_account(domain, api_key):
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {api_key}"
        }
        tickets_url = f"https://{domain}/api/v2/tickets"
        params = {
            "per_page": 100  # Fetch 100 tickets per page (maximum limit)
        }

        try:
            while True:
                response = requests.get(tickets_url, headers=headers, params=params)
                if response.status_code != 200:
                    return {"error": f"Failed to fetch tickets from {domain}: {response.json()}"}, response.status_code

                tickets = response.json().get("tickets", [])
                if not tickets:
                    return {"message": f"No tickets found or all tickets have been deleted on {domain}."}, 200

                # Delete each ticket
                for ticket in tickets:
                    ticket_id = ticket.get("id")
                    delete_url = f"{tickets_url}/{ticket_id}"
                    delete_response = requests.delete(delete_url, headers=headers)

                    if delete_response.status_code == 204:
                        print(f"Ticket {ticket_id} deleted successfully on {domain}.")
                    else:
                        print(f"Failed to delete ticket {ticket_id} on {domain}: {delete_response.json()}")

                # Check if there are more pages
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

    # Aggregate results
    error_messages = [result["error"] for result in results if "error" in result["result"]]
    success_messages = [result["result"]["message"] for result in results if "message" in result["result"]]

    if error_messages:
        return JsonResponse({"errors": error_messages}, status=500)
    
    return JsonResponse({"messages": success_messages}, status=200)    

@csrf_exempt
def gaut(request):
    from .scheduler import get_all_tickets_and_update
    req = get_all_tickets_and_update()
    return JsonResponse({
        "message":req
    })


@csrf_exempt
def createTicketManually(request):
    from .scheduler import call_create_ticket
    req = call_create_ticket()
    return JsonResponse({
        "message":"hello world"
    })

@csrf_exempt
def updateTicketManually(request):
    from .scheduler import updateExploitsAndPatches
    req = updateExploitsAndPatches()
    return JsonResponse({
        "message":"hello world"
    })