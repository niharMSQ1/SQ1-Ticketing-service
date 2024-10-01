import ast
import json
import requests
import logging
import threading
import re
import pytz

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.date import DateTrigger

from datetime import datetime, timedelta, time

from django.http import JsonResponse

from django.template.loader import render_to_string

from requests.auth import HTTPBasicAuth


from .dbUtils import get_connection
from .models import *
from .ticketing_service import save_ticket_details

logging.basicConfig()
logging.getLogger('apscheduler').setLevel(logging.DEBUG)

lock = threading.Lock()

def freshservice_call_create_ticket():
    with lock:    
        connection = get_connection()
        if not connection or not connection.is_connected():
            return JsonResponse({"error": "Failed to connect to the database"}, status=500)

        try:
            with connection.cursor(dictionary=True) as cursor:
                cursor.execute("SELECT * FROM vulnerabilities;")
                results = cursor.fetchall()
                existing_vul_ids = TicketingServiceDetails.objects.filter(ticketServicePlatform="Freshservice")
                
                if len(existing_vul_ids) == 0:
                    for result in results:
                        vul_id = result.get("id")
                        organization_id = result.get("organization_id")

                        if vul_id not in existing_vul_ids:

                            cursor.execute("""
                            SELECT assetable_type, assetable_id
                            FROM assetables
                            WHERE vulnerabilities_id = %s
                        """, (vul_id,))
                        assetables_results = cursor.fetchall()

                        assets = {
                            "servers": [],
                            "workstations": []
                        }
                        ass_type = []
                        for i in assetables_results:
                            ass_type.append(i['assetable_type'])

                        ass_id = []
                        for i in assetables_results:
                            ass_id.append(i['assetable_id'])
                        
                        index = 0
                        for i in ass_type:
                            j = ass_id[index]
                            if i == 'App\\Models\\Workstations':
                                cursor.execute("""
                                SELECT host_name, ip_address
                                FROM workstations
                                WHERE id = %s AND organization_id = %s
                                """, (j, organization_id))
                                workstation = cursor.fetchone()
                                if workstation:
                                    assets["workstations"].append(workstation)
                                index = index+1
                            
        
                            if i == 'App\\Models\\Servers':
                                cursor.execute("""
                                SELECT host_name, ip_address
                                FROM workstations
                                WHERE id = %s AND organization_id = %s
                                """, (j, organization_id))
                                server = cursor.fetchone()
                                if server:
                                    assets["servers"].append(server)
                                index = index+1


                        mapped_priority = None
                        mapped_priority_html = None

                        risk = float(result.get("risk"))

                        if 9.0 <= risk <= 10.0:
                            mapped_priority = 4
                            mapped_priority_html = f"<strong>Risk:</strong><strong style='color: #880808;'> Critical</strong><br><br>"
                        elif 7.0 <= risk <= 8.9:
                            mapped_priority = 3
                            mapped_priority_html = f"<strong>Risk:</strong><strong style='color: #AA4A44;'> High</strong><br><br>"
                        elif 4.0 <= risk <= 6.9:
                            mapped_priority = 2
                            mapped_priority_html = f"<strong>Risk:</strong><strong style='color: #FFC300;'> Medium</strong><br><br>"
                        elif 0.1 <= risk <= 3.9:
                            mapped_priority = 1
                            mapped_priority_html = f"<strong>Risk:</strong><strong style='color: #00FF28;'> Medium</strong><br><br>"

                        cursor.execute("SELECT * FROM exploits WHERE vul_id = %s AND organization_id = %s", (vul_id, organization_id))
                        exploits = cursor.fetchall()
                        exploitIdList = []
                        if exploits !=[]:
                            for exploit in exploits:
                                exploitIdList.append(exploit.get("id"))

                        cursor.execute("SELECT * FROM patch WHERE vul_id = %s", (vul_id,))
                        patches = cursor.fetchall()
                        patchesIdList = []
                        if patches !=[]:
                            for patch in patches:
                                patchesIdList.append(patch.get("id"))

                        cursor.execute("SELECT * FROM ticketing_tool WHERE organization_id = %s AND type = 'Freshservice'", (organization_id,))
                        ticketing_tool = cursor.fetchone()

                        if not ticketing_tool:
                            continue

                        freshservice_url = (json.loads((ticketing_tool.get("values")))).get("url") + "/api/v2/tickets"
                        freshservice_key =(json.loads((ticketing_tool.get("values")))).get("key") 

                        requestedForEmail = (json.loads(ticketing_tool.get('values'))).get('email')

                        resultCVEs = json.loads(result.get("CVEs", {}))
                        if isinstance(resultCVEs, dict):
                            cve_list = resultCVEs.get("cves", [])
                        else:
                            cve_list = []
                        cve_string = ", ".join(cve_list)
                        context = {
                            'result': {
                                'CVEs': cve_string,
                                'severity': result.get('severity'),
                                'first_seen': result.get('first_seen'),
                                'last_identified_on': result.get('last_identified_on'),
                                'patch_priority': result.get('patch_priority'),
                            }
                        }

                        detection_summary_table = render_to_string('detection_summary_table.html', context)
                        remediation_table = render_to_string('remediation_table.html', {'result': result}) if result else render_to_string('remediation_table.html', {'result': None})
                        exploits_table_html = render_to_string('exploits_table.html', {'exploits': exploits}) if exploits else render_to_string('exploits_table.html', {'exploits': None})

                        if patches:
                            patch_data = []
                            for patch in patches:
                                patchSolution = patch.get("solution", "")
                                patchDescription = patch.get("description", "")
                                patchComplexity = patch.get("complexity", "")
                                patchType = patch.get("type", "")
                                os_list = json.loads(patch.get("os", "[]"))
                                patchOs = ", ".join(f"{os['os_name']}-{os['os_version']}" for os in os_list)

                                patch_data.append({
                                    'solution': patchSolution,
                                    'description': patchDescription,
                                    'complexity': patchComplexity,
                                    'type': patchType,
                                    'os': patchOs,
                                    'url': patch.get("url", "")
                                })

                            patchContext = {
                                'patches': patch_data
                            }
                        else:
                            patchContext = {
                                'patches': []
                            }

                        patch_table_html = render_to_string('patch_table.html', patchContext)
                        workstation_table = render_to_string('workstation_table.html', {'workstations': assets['workstations']})
                        servers_table = render_to_string('servers_table.html', {'servers': assets['servers']})

                        description = f"<strong>Vulnerability synopsis:</strong> {result['description']}" if result['description'] is not None else "<strong>Vulnerability synopsis:</strong> NA"


                        combined_data = {
                            "description": mapped_priority_html+description+ detection_summary_table+remediation_table+ exploits_table_html + patch_table_html+workstation_table+servers_table,
                            "subject": result.get("name"),
                            "email": requestedForEmail,
                            "priority": mapped_priority,
                            "status": 2,
                            "cc_emails": [],
                            "workspace_id": 2,
                            "urgency": 3,
                        }

                        headers = {
                            "Content-Type": "application/json",
                            "Authorization": f"Basic {freshservice_key}"
                        }
                        response = requests.post(freshservice_url, json=combined_data, headers=headers)
                        if response.status_code == 201:
                            ticket_id = response.json()['ticket'].get("id")
                            ticket_data = response.json().get("ticket", {})
                            checkVulIdExists = TicketingServiceDetails.objects.filter(cVulId=([key for key, value in TICKET_REFERENCE_CHOICES if value == 'Freshservice'][0] + "-" +str(vul_id))).exists()

                            if not checkVulIdExists:
                                save_ticket_details(ticket_data, vul_id, exploitIdList, patchesIdList, organization_id)
                                print(f"Ticket created successfully for vulnerabilities.")
                            else:
                                delete_url = f"{freshservice_url}/{ticket_id}"
                                delete_response = requests.delete(delete_url, headers=headers)
                                if delete_response.status_code == 204:
                                    print(f"Ticket {ticket_id} deleted successfully.")
                                else:
                                    print(f"Failed to delete ticket {ticket_id}, status code: {delete_response.status_code}")

                        else:
                            print(f"Failed to create ticket, status code: {response.status_code}")

                    return JsonResponse({"status":"Success", "message": f"tickets created successfully."}, status=200)

                else:
                    latest_existing_id = int((existing_vul_ids.last().cVulId).split('-')[1])

                    if results[-1]["id"] == latest_existing_id:
                        return JsonResponse({"status":"No new vulnerabilities","message": "Nothing to add"}, status=200)
                    
                    elif results[-1]["id"] > latest_existing_id:
                        new_vulnerabilities = [vul for vul in results if vul["id"] > latest_existing_id]

                        for result in new_vulnerabilities:
                            vul_id = result.get("id")
                            organization_id = result.get("organization_id")
                            if vul_id not in list(TicketingServiceDetails.objects.values_list('sq1VulId', flat=True)):

                                cursor.execute("""
                                SELECT assetable_type, assetable_id
                                FROM assetables
                                WHERE vulnerabilities_id = %s
                            """, (vul_id,))
                            assetables_results = cursor.fetchall()

                            assets = {
                                "servers": [],
                                "workstations": []
                            }
                            ass_type = []
                            for i in assetables_results:
                                ass_type.append(i['assetable_type'])

                            ass_id = []
                            for i in assetables_results:
                                ass_id.append(i['assetable_id'])
                            
                            index = 0
                            for i in ass_type:
                                j = ass_id[index]
                                if i == 'App\\Models\\Workstations':
                                    cursor.execute("""
                                    SELECT host_name, ip_address
                                    FROM workstations
                                    WHERE id = %s AND organization_id = %s
                                    """, (j, organization_id))
                                    workstation = cursor.fetchone()
                                    if workstation:
                                        assets["workstations"].append(workstation)
                                    index = index+1
                                
            
                                if i == 'App\\Models\\Servers':
                                    cursor.execute("""
                                    SELECT host_name, ip_address
                                    FROM workstations
                                    WHERE id = %s AND organization_id = %s
                                    """, (j, organization_id))
                                    server = cursor.fetchone()
                                    if server:
                                        assets["servers"].append(server)
                                    index = index+1

                            mapped_priority = None
                            mapped_priority_html = None

                            risk = float(result.get("risk"))

                            if 9.0 <= risk <= 10.0:
                                mapped_priority = 4
                                mapped_priority_html = f"<strong>Risk:</strong><strong style='color: #880808;'> Critical</strong><br><br>"
                            elif 7.0 <= risk <= 8.9:
                                mapped_priority = 3
                                mapped_priority_html = f"<strong>Risk:</strong><strong style='color: #AA4A44;'> High</strong><br><br>"
                            elif 4.0 <= risk <= 6.9:
                                mapped_priority = 2
                                mapped_priority_html = f"<strong>Risk:</strong><strong style='color: #FFC300;'> Medium</strong><br><br>"
                            elif 0.1 <= risk <= 3.9:
                                mapped_priority = 1
                                mapped_priority_html = f"<strong>Risk:</strong><strong style='color: #00FF28;'> Medium</strong><br><br>"

                            cursor.execute("SELECT * FROM exploits WHERE vul_id = %s AND organization_id = %s", (vul_id, organization_id))
                            exploits = cursor.fetchall()
                            exploitIdList = []
                            if exploits !=[]:
                                for exploit in exploits:
                                    exploitIdList.append(exploit.get("id"))

                            cursor.execute("SELECT * FROM patch WHERE vul_id = %s", (vul_id,))
                            patches = cursor.fetchall()
                            patchesIdList = []
                            if patches !=[]:
                                for patch in patches:
                                    patchesIdList.append(patch.get("id"))

                            cursor.execute("SELECT * FROM ticketing_tool WHERE organization_id = %s AND type = 'Freshservice'", (organization_id,))
                            ticketing_tool = cursor.fetchone()

                            if not ticketing_tool:
                                continue

                            freshservice_url = (json.loads((ticketing_tool.get("values")))).get("url") + "/api/v2/tickets"
                            freshservice_key =(json.loads((ticketing_tool.get("values")))).get("key")

                            requestedForEmail = (json.loads(ticketing_tool.get('values'))).get('email')

                            resultCVEs = json.loads(result.get("CVEs", {}))
                            if isinstance(resultCVEs, dict):
                                cve_list = resultCVEs.get("cves", [])
                            else:
                                cve_list = []
                            cve_string = ", ".join(cve_list)
                            context = {
                                'result': {
                                    'CVEs': cve_string,
                                    'severity': result.get('severity'),
                                    'first_seen': result.get('first_seen'),
                                    'last_identified_on': result.get('last_identified_on'),
                                    'patch_priority': result.get('patch_priority'),
                                }
                            }

                            detection_summary_table = render_to_string('detection_summary_table.html', context)
                            remediation_table = render_to_string('remediation_table.html', {'result': result}) if result else render_to_string('remediation_table.html', {'result': None})
                            exploits_table_html = render_to_string('exploits_table.html', {'exploits': exploits}) if exploits else render_to_string('exploits_table.html', {'exploits': None})

                            if patches:
                                patch_data = []
                                for patch in patches:
                                    patchSolution = patch.get("solution", "")
                                    patchDescription = patch.get("description", "")
                                    patchComplexity = patch.get("complexity", "")
                                    patchType = patch.get("type", "")
                                    os_list = json.loads(patch.get("os", "[]"))
                                    patchOs = ", ".join(f"{os['os_name']}-{os['os_version']}" for os in os_list)

                                    patch_data.append({
                                        'solution': patchSolution,
                                        'description': patchDescription,
                                        'complexity': patchComplexity,
                                        'type': patchType,
                                        'os': patchOs,
                                        'url': patch.get("url", "")
                                    })

                                patchContext = {
                                    'patches': patch_data
                                }
                            else:
                                patchContext = {
                                    'patches': []
                                }

                            patch_table_html = render_to_string('patch_table.html', patchContext)
                            workstation_table = render_to_string('workstation_table.html', {'workstations': assets['workstations']})
                            servers_table = render_to_string('servers_table.html', {'servers': assets['servers']})

                            descriptionText = f"<strong>Vulnerability synopsis:</strong> {result['description']}" if result['description'] is not None else "<strong>Vulnerability synopsis:</strong> NA"
                            combined_data = {
                                "description":mapped_priority+ descriptionText + detection_summary_table+remediation_table+ exploits_table_html + patch_table_html+workstation_table+servers_table,
                                "subject": result.get("name"),
                                "email": requestedForEmail,
                                "priority": mapped_priority,
                                "status": 2,
                                "cc_emails": [],
                                "workspace_id": 2,
                                "urgency": 3,
                            }

                            headers = {
                                "Content-Type": "application/json",
                                "Authorization": f"Basic {freshservice_key}"
                            }

                            response = requests.post(freshservice_url, json=combined_data, headers=headers)

                            if response.status_code == 201:
                                ticket_id = response.json()['ticket'].get("id")
                                ticket_data = response.json().get("ticket", {})

                                checkVulIdExists = TicketingServiceDetails.objects.filter(cVulId=([key for key, value in TICKET_REFERENCE_CHOICES if value == 'Freshservice'][0] + "-" +str(vul_id))).exists()

                                if not checkVulIdExists:
                                    save_ticket_details(ticket_data, vul_id, exploitIdList, patchesIdList, organization_id)
                                    print(f"Ticket created successfully for vulnerabilities.")
                                else:
                                    delete_url = f"{freshservice_url}/{ticket_id}"
                                    delete_response = requests.delete(delete_url, headers=headers)
                                    if delete_response.status_code == 204:
                                        print(f"Ticket {ticket_id} deleted successfully.")
                                    else:
                                        print(f"Failed to delete ticket {ticket_id}, status code: {delete_response.status_code}")

                            else:
                                print(f"Failed to create ticket, status code: {response.status_code}")

                        return JsonResponse({"status":"Success" , "message": "tickets created successfully."}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

        finally:
            if connection.is_connected():
                connection.close()
                pass

def updateExploitsAndPatchesForFreshservice():
    try:
        connection = get_connection()
        if not connection or not connection.is_connected():
            return JsonResponse({"error": "Failed to connect to the database"}, status=500)
        
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM ticketing_tool WHERE type = 'Freshservice'")
            ticketing_tools = cursor.fetchall()

            all_tickets = []

            for tool in ticketing_tools:
                try:
                    values = json.loads(tool.get("values"))
                    url = values.get("url")
                    key = values.get("key")
                    requestedForEmail = json.loads(tool['values']).get("email")
                    
                    headers = {
                        "Content-Type": "application/json",
                        "Authorization": f"Basic {key}"
                    }

                    params = {"per_page": 100}
                    response = requests.get(f"{url}/api/v2/tickets", headers=headers, params=params)

                    if response.status_code == 200:
                        tickets = response.json().get('tickets', [])
                        all_tickets.extend(tickets)
                    else:
                        print(f"Error fetching tickets for {url}: {response.status_code} - {response.text}")
                        return JsonResponse({
                            "error": f"Error fetching tickets for {url}",
                            "status_code": response.status_code,
                            "message": response.text
                        }, status=response.status_code)

                except requests.RequestException as e:
                    print(f"Request failed for {url}: {str(e)}")
                    return JsonResponse({"error": f"Request failed for {url}: {str(e)}"}, status=500)
                
            for ticket in all_tickets:
                try:
                    if TicketingServiceDetails.objects.filter(ticketId=ticket.get("id")).exists():
                        ticket_obj = TicketingServiceDetails.objects.get(ticketId=ticket.get("id"))
                        vulnerabilityId = ticket_obj.sq1VulId
                        organizationId = ticket_obj.organizationId

                        exploits_list = ast.literal_eval(ticket_obj.exploitsList)
                        patches_list = ast.literal_eval(ticket_obj.patchesList)

                        cursor.execute(f"SELECT * FROM exploits WHERE vul_id = {vulnerabilityId}")
                        exploits = cursor.fetchall()

                        cursor.execute(f"SELECT * FROM patch WHERE vul_id = {vulnerabilityId}")
                        patches = cursor.fetchall()

                        if len(patches) > len(patches_list) or len(exploits) > len(exploits_list):
                            cursor.execute(f"SELECT * FROM vulnerabilities WHERE id = {vulnerabilityId}")
                            result = cursor.fetchall()

                            if not result:
                                return JsonResponse({"error": "Vulnerability not found"}, status=404)

                            risk = float(result[0].get("risk"))
                            mapped_priority = determine_priority(risk)

                            cursor.execute("SELECT * FROM exploits WHERE vul_id = %s AND organization_id = %s", (vulnerabilityId, organizationId))
                            exploits = cursor.fetchall()

                            cursor.execute("SELECT * FROM patch WHERE vul_id = %s", (vulnerabilityId,))
                            patches = cursor.fetchall()

                            combined_data = generate_combined_data(cursor, result, vulnerabilityId, organizationId, exploits, patches, requestedForEmail)

                            update_url = f"{url}/api/v2/tickets/{ticket.get('id')}"
                            response = requests.put(update_url, json=combined_data, headers=headers)

                            if response.status_code == 200:
                                update_ticket_details(ticket_obj, patches, exploits, patches_list, exploits_list)
                            else:
                                print(f"Error updating Freshservice ticket {ticket.get('id')}: {response.status_code} - {response.text}")
                                return JsonResponse({
                                    "error": f"Error updating Freshservice ticket {ticket.get('id')}",
                                    "status_code": response.status_code,
                                    "message": response.text
                                }, status=response.status_code)
                    else:
                        print(f"Ticket with ID {ticket.get('id')} does not exist in the local database.")

                except Exception as e:
                    print(f"Error processing ticket {ticket.get('id')}: {str(e)}")
                    return JsonResponse({"error": f"Error processing ticket {ticket.get('id')}: {str(e)}"}, status=500)

            return JsonResponse({"message": "Tickets updated successfully"}, status=200)

    except Exception as e:
        print(f"Unexpected error occurred: {str(e)}")
        return JsonResponse({"error": f"Unexpected error occurred: {str(e)}"}, status=500)

def determine_priority(risk):
    if 9.0 <= risk <= 10.0:
        return 4
    elif 7.0 <= risk <= 8.9:
        return 3
    elif 4.0 <= risk <= 6.9:
        return 2
    elif 0.1 <= risk <= 3.9:
        return 1
    return None

def generate_combined_data(cursor, result, vulnerabilityId, organizationId, exploits, patches, requestedForEmail):
    resultCVEs = json.loads(result[0].get("CVEs", "[]"))
    cve_list = resultCVEs.get("cves", []) if isinstance(resultCVEs, dict) else []
    cve_string = ", ".join(cve_list)

    context = {
        'result': {
            'CVEs': cve_string,
            'severity': result[0].get('severity'),
            'first_seen': result[0].get('first_seen'),
            'last_identified_on': result[0].get('last_identified_on'),
            'patch_priority': result[0].get('patch_priority'),
        }
    }

    if patches:
        patch_data = []
        for patch in patches:
            patchSolution = patch.get("solution", "")
            patchDescription = patch.get("description", "")
            patchComplexity = patch.get("complexity", "")
            patchType = patch.get("type", "")
            os_list = json.loads(patch.get("os", "[]"))
            patchOs = ", ".join(f"{os['os_name']}-{os['os_version']}" for os in os_list)

            patch_data.append({
                'solution': patchSolution,
                'description': patchDescription,
                'complexity': patchComplexity,
                'type': patchType,
                'os': patchOs,
                'url': patch.get("url", "")
            })

        patchContext = {
            'patches': patch_data
        }
    else:
        patchContext = {
            'patches': []
        }

    mapped_priority = None
    mapped_priority_html = None

    risk = float((result[0]).get("risk"))

    if 9.0 <= risk <= 10.0:
        mapped_priority = 4
        mapped_priority_html = f"<strong>Risk:</strong><strong style='color: #880808;'> Critical</strong><br><br>"
    elif 7.0 <= risk <= 8.9:
        mapped_priority = 3
        mapped_priority_html = f"<strong>Risk:</strong><strong style='color: #AA4A44;'> High</strong><br><br>"
    elif 4.0 <= risk <= 6.9:
        mapped_priority = 2
        mapped_priority_html = f"<strong>Risk:</strong><strong style='color: #FFC300;'> Medium</strong><br><br>"
    elif 0.1 <= risk <= 3.9:
        mapped_priority = 1
        mapped_priority_html = f"<strong>Risk:</strong><strong style='color: #00FF28;'> Medium</strong><br><br>"

    assetables_results = cursor.fetchall()
    assets = get_assets(cursor, assetables_results, organizationId)

    detection_summary_table = render_to_string('detection_summary_table.html', context)
    remediation_table = render_to_string('remedieationTableUpd.html', {'solutionPatch': result[0].get("solution_patch")})
    exploits_table_html = render_to_string('exploits_table.html', {'exploits': exploits})
    patch_table_html = render_to_string('patch_table.html', patchContext)
    workstation_table = render_to_string('workstation_table.html', {'workstations': assets['workstations']})
    servers_table = render_to_string('servers_table.html', {'servers': assets['servers']})

    descriptionTxt = result[0].get('description') if  result[0].get('description') else "No description added"

    combined_data = {
        "description": mapped_priority_html+descriptionTxt +detection_summary_table + remediation_table + exploits_table_html + patch_table_html + workstation_table + servers_table,
        "subject": result[0].get('name'),
        "email": requestedForEmail,
        "priority": 4,
        "status": 2,
        "cc_emails": [],
        "workspace_id": 2,
        "urgency": 3,
    }
    return combined_data

def update_ticket_details(ticket_obj, patches, exploits, patches_list, exploits_list):
    new_patch_ids = [patch['id'] for patch in patches if patch['id'] not in patches_list]
    new_exploit_ids = [exploit['id'] for exploit in exploits if exploit['id'] not in exploits_list]

    if new_patch_ids:
        existing_patch_ids = ast.literal_eval(ticket_obj.patchesList or '[]')
        ticket_obj.patchesList = str(existing_patch_ids + new_patch_ids)
    
    if new_exploit_ids:
        existing_exploit_ids = ast.literal_eval(ticket_obj.exploitsList or '[]')
        ticket_obj.exploitsList = str(existing_exploit_ids + new_exploit_ids)

    ticket_obj.save()

def get_assets(cursor, assetables_results, organizationId):
    assets = {
        "servers": [],
        "workstations": []
    }
    ass_type = [i['assetable_type'] for i in assetables_results]
    ass_id = [i['assetable_id'] for i in assetables_results]

    for i, asset_type in enumerate(ass_type):
        asset_id = ass_id[i]
        if asset_type == 'App\\Models\\Workstations':
            cursor.execute("SELECT host_name, ip_address FROM workstations WHERE id = %s AND organization_id = %s", (asset_id, organizationId))
            workstation = cursor.fetchone()
            if workstation:
                assets["workstations"].append(workstation)
        elif asset_type == 'App\\Models\\Servers':
            cursor.execute("SELECT host_name, ip_address FROM servers WHERE id = %s AND organization_id = %s", (asset_id, organizationId))
            server = cursor.fetchone()
            if server:
                assets["servers"].append(server)

    return assets

def jira_call_create_ticket():
    connection = get_connection()
    if not connection or not connection.is_connected():
        return JsonResponse({"error": "Failed to connect to the database"}, status=500)

    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM vulnerabilities;")
            results = cursor.fetchall()
            existing_vul_ids = TicketingServiceDetails.objects.filter(ticketServicePlatform="JIRA")

            if len(existing_vul_ids) == 0:
                for result in results:
                    vul_id = result.get("id")
                    organization_id = result.get("organization_id")

                    if vul_id not in existing_vul_ids:

                        cursor.execute("""
                        SELECT assetable_type, assetable_id
                        FROM assetables
                        WHERE vulnerabilities_id = %s
                    """, (vul_id,))
                    assetables_results = cursor.fetchall()

                    assets = {
                        "servers": [],
                        "workstations": []
                    }
                    ass_type = []
                    for i in assetables_results:
                        ass_type.append(i['assetable_type'])

                    ass_id = []
                    for i in assetables_results:
                        ass_id.append(i['assetable_id'])
                    
                    index = 0
                    for i in ass_type:
                        j = ass_id[index]
                        if i == 'App\\Models\\Workstations':
                            cursor.execute("""
                            SELECT host_name, ip_address
                            FROM workstations
                            WHERE id = %s AND organization_id = %s
                            """, (j, organization_id))
                            workstation = cursor.fetchone()
                            if workstation:
                                assets["workstations"].append(workstation)
                            index = index+1
                        
    
                        if i == 'App\\Models\\Servers':
                            cursor.execute("""
                            SELECT host_name, ip_address
                            FROM workstations
                            WHERE id = %s AND organization_id = %s
                            """, (j, organization_id))
                            server = cursor.fetchone()
                            if server:
                                assets["servers"].append(server)
                            index = index+1

                    mapped_priority = None

                    risk = float(result.get("risk"))

                    if 9.0 <= risk <= 10.0:
                            mapped_priority = "Highest"
                    elif 7.0 <= risk <= 8.9:
                        mapped_priority = "High"
                    elif 4.0 <= risk <= 6.9:
                        mapped_priority = "Medium"
                    elif 0.1 <= risk <= 3.9:
                        mapped_priority = "Low"

                    cursor.execute("SELECT * FROM exploits WHERE vul_id = %s AND organization_id = %s", (vul_id, organization_id))
                    exploits = cursor.fetchall()
                    exploitIdList = []
                    if exploits !=[]:
                        for exploit in exploits:
                            exploitIdList.append(exploit.get("id"))

                    cursor.execute("SELECT * FROM patch WHERE vul_id = %s", (vul_id,))
                    patches = cursor.fetchall()
                    patchesIdList = []
                    if patches !=[]:
                        for patch in patches:
                            patchesIdList.append(patch.get("id"))

                    cursor.execute("SELECT * FROM ticketing_tool WHERE organization_id = %s AND type = 'Jira'", (organization_id,))
                    ticketing_tool = cursor.fetchone()

                    if not ticketing_tool:
                        continue

                    jira_url = (json.loads(ticketing_tool.get("values"))).get('url') + "/rest/api/3/issue/"
                    jira_key =(json.loads(ticketing_tool.get("values"))).get('password')
                    boardName = (json.loads(ticketing_tool.get("values"))).get('board')


                    resultCVEs = json.loads(result.get("CVEs", {}))
                    if isinstance(resultCVEs, dict):
                        cve_list = resultCVEs.get("cves", [])
                    else:
                        cve_list = []
                    cve_string = ", ".join(cve_list)
                    context = {
                        'result': {
                            'CVEs': cve_string,
                            'severity': result.get('severity'),
                            'first_seen': result.get('first_seen'),
                            'last_identified_on': result.get('last_identified_on'),
                            'patch_priority': result.get('patch_priority'),
                        }
                    }

                    if patches:
                        patch_data = []
                        for patch in patches:
                            patchSolution = patch.get("solution", "")
                            patchDescription = patch.get("description", "")
                            patchComplexity = patch.get("complexity", "")
                            patchType = patch.get("type", "")
                            os_list = json.loads(patch.get("os", "[]"))
                            patchOs = ", ".join(f"{os['os_name']}-{os['os_version']}" for os in os_list)

                            patch_data.append({
                                'solution': patchSolution,
                                'description': patchDescription,
                                'complexity': patchComplexity,
                                'type': patchType,
                                'os': patchOs,
                                'url': patch.get("url", "")
                            })

                        patchContext = {
                            'patches': patch_data
                        }
                    else:
                        patchContext = {
                            'patches': []
                        }

                    remediationObj = {
                        "solution_patch": result["solution_patch"],
                        "solution_workaround": result["solution_workaround"],
                        "preventive_measure": result["preventive_measure"],
                        }
                    cves = json.loads(result["CVEs"])
                    cves_string = ", ".join(cves["cves"])
                    detectionSummaryObj = {
                        "CVE": cves_string,
                        "Severity": result["severity"],
                        "first_identified_on": result["first_seen"],
                        "last_identifies_on":result["last_identified_on"],
                        "patch_priority":result["patch_priority"]
                        }

                    vulnerability_description = None
                    if result['description'] is not None:
                        vulnerability_description = re.sub(r'\s+', ' ', re.sub(r'<.*?>', '', "Vulnerability synopsis: "+ result['description'])).strip()
                    else:
                        vulnerability_description = "Vulnerability synopsis: Description not aded"

                    workstations = assets['workstations']

                    def convert_none_workstations(data):
                        for workstation in workstations:
                            for key, value in workstation.items():
                                if value is None:
                                    workstation[key]="NA"
                        return data

                    workstations = convert_none_workstations(workstations)

                    servers = assets['servers']

                    def convert_none_servers(data):
                        for server in servers:
                            for key, value in server.items():
                                if value is None:
                                    server[key]="NA"
                        return data

                    servers = convert_none_servers(servers)

                    listOfDetection = [detectionSummaryObj]

                    def convert_datetime_to_string(data):
                        for item in data:
                            for key, value in item.items():
                                if isinstance(value, datetime):
                                    item[key] = value.strftime('%Y-%m-%d %H:%M:%S')
                        return data
                    
                    listOfDetection = convert_datetime_to_string(listOfDetection)

                    for detection in listOfDetection:
                        for key, value in detection.items():
                            if value is None:
                                detection[key] = "NA"

                    listOfRemediation = [remediationObj]

                    def convert_none(data):
                        for remediation in listOfRemediation:
                            for key, value in remediation.items():
                                if value is None:
                                    remediation[key]="NA"
                        return data

                    listOfRemediation = convert_none(listOfRemediation)

                    allExploits = exploits
                    def convert_none_for_exploits(data):
                        for exploit in allExploits:
                            for key, value in exploit.items():
                                if value is None:
                                    exploit[key]="NA"
                        return data
                    allExploits = convert_none_for_exploits(allExploits)
                    allExploits = [{**exploit, 'dependency': 'Dependent on other exploits' if exploit['dependency'] == 'yes' else 'Self exploitable'} for exploit in allExploits]

                    allPatches = [
                        {
                            **patch,
                            'os': ', '.join([f"{os['os_name']}-{os['os_version']}" for os in json.loads(patch['os'])])
                        } for patch in patches
                    ]


                    def convert_none_for_patches(data):
                        for patch in allPatches:
                            for key, value in patch.items():
                                if value is None:
                                    patch[key]="NA"
                        return data
                    allPatches = convert_none_for_patches(allPatches)
                    
                    username = (json.loads(ticketing_tool.get("values"))).get('username')
                    password = jira_key

                    combined_data = {
                        "fields": {
                            "project": {
                                "key": boardName
                            },
                            "summary": result['name'],
                            "description": {
                                "version": 1,
                                "type": "doc",
                                "content": [
                                    {
                                        "type": "paragraph",
                                        "content": [
                                            {
                                                "type": "text",
                                                "text": vulnerability_description
                                            }
                                        ]
                                    },
                                    {
                                        "type": "paragraph",
                                        "content": [
                                            {
                                                "type": "text",
                                                "text": "Detection Summary:"
                                            }
                                        ]
                                    },
                                    *(
                                        [
                                            {
                                                "type": "table",
                                                "attrs": {
                                                    "isNumberColumnEnabled": False,
                                                    "layout": "default"
                                                },
                                                "content": [
                                                    {
                                                        "type": "tableRow",
                                                        "content": [
                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "CVE"}]}]},
                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "First Identified On"}]}]},
                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Severity"}]}]},
                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Last Identified On"}]}]},
                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Patch Priority"}]}]}
                                                        ]
                                                    },
                                                    *[
                                                        {
                                                            "type": "tableRow",
                                                            "content": [
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": det["CVE"]}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": det["first_identified_on"]}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": det["Severity"]}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": det["last_identifies_on"]}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": det["patch_priority"]}]}]}
                                                            ]
                                                        }
                                                        for det in listOfDetection
                                                    ]
                                                ]
                                            }
                                        ] if listOfDetection else [
                                            {
                                                "type": "paragraph",
                                                "content": [
                                                    {
                                                        "type": "text",
                                                        "text": "No detection data available."
                                                    }
                                                ]
                                            }
                                        ]
                                    ),
                                    # Remediation Summary section
                                    {
                                        "type": "paragraph",
                                        "content": [
                                            {
                                                "type": "text",
                                                "text": "Remediation:"
                                            }
                                        ]
                                    },
                                    *(
                                        [
                                            {
                                                "type": "table",
                                                "attrs": {
                                                    "isNumberColumnEnabled": False,
                                                    "layout": "default"
                                                },
                                                "content": [
                                                    {
                                                        "type": "tableRow",
                                                        "content": [
                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Solution Patch"}]}]},
                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Solution Workaround"}]}]},
                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Preventive Measure"}]}]}
                                                        ]
                                                    },
                                                    *[
                                                        {
                                                            "type": "tableRow",
                                                            "content": [
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": re.sub(r'\s+', ' ', re.sub(r'<.*?>', '', rem["solution_patch"])).strip()}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": re.sub(r'\s+', ' ', re.sub(r'<.*?>', '', rem["solution_workaround"])).strip()}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": re.sub(r'\s+', ' ', re.sub(r'<.*?>', '', rem["preventive_measure"])).strip()}]}]}
                                                            ]
                                                        }
                                                        for rem in listOfRemediation
                                                    ]
                                                ]
                                            }
                                        ] if listOfRemediation else [
                                            {
                                                "type": "paragraph",
                                                "content": [
                                                    {
                                                        "type": "text",
                                                        "text": "No remediation data available."
                                                    }
                                                ]
                                            }
                                        ]
                                    ),
                                    # Exploits Summary section
                                    {
                                        "type": "paragraph",
                                        "content": [
                                            {
                                                "type": "text",
                                                "text": "Exploits Table:"
                                            }
                                        ]
                                    },
                                    *(
                                        [
                                            {
                                                "type": "table",
                                                "attrs": {
                                                    "isNumberColumnEnabled": False,
                                                    "layout": "default"
                                                },
                                                "content": [
                                                    {
                                                        "type": "tableRow",
                                                        "content": [
                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Exploit Name"}]}]},
                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Description"}]}]},
                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Complexity"}]}]},
                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Dependency"}]}]}
                                                        ]
                                                    },
                                                    *[
                                                        {
                                                            "type": "tableRow",
                                                            "content": [
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": exp["name"]}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": exp["description"]}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": exp["complexity"]}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": exp["dependency"]}]}]}
                                                            ]
                                                        }
                                                        for exp in allExploits
                                                    ]
                                                ]
                                            }
                                        ] if allExploits else [
                                            {
                                                "type": "paragraph",
                                                "content": [
                                                    {
                                                        "type": "text",
                                                        "text": "No exploit data available."
                                                    }
                                                ]
                                            }
                                        ]
                                    ),
                                    # Patch Summary section
                                    {
                                        "type": "paragraph",
                                        "content": [
                                            {
                                                "type": "text",
                                                "text": "Patch(es):"
                                            }
                                        ]
                                    },
                                    *(
                                        [
                                            {
                                                "type": "table",
                                                "attrs": {
                                                    "isNumberColumnEnabled": False,
                                                    "layout": "default"
                                                },
                                                "content": [
                                                    {
                                                        "type": "tableRow",
                                                        "content": [
                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Patch Solution"}]}]},
                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Description"}]}]},
                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Complexity"}]}]},
                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "URL"}]}]},
                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Type"}]}]},
                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "OS"}]}]}
                                                        ]
                                                    },
                                                    *[
                                                        {
                                                            "type": "tableRow",
                                                            "content": [
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": patch["solution"]}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": patch["description"]}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": patch["complexity"]}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": patch["url"]}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": patch["type"]}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": patch["os"]}]}]}
                                                            ]
                                                        }
                                                        for patch in allPatches
                                                    ]
                                                ]
                                            }
                                        ] if allPatches else [
                                            {
                                                "type": "paragraph",
                                                "content": [
                                                    {
                                                        "type": "text",
                                                        "text": "No patch data available."
                                                    }
                                                ]
                                            }
                                        ]
                                    ),
                                    # Workstations Summary section
                                    {
                                        "type": "paragraph",
                                        "content": [
                                            {
                                                "type": "text",
                                                "text": "Workstations:"
                                            }
                                        ]
                                    },
                                    *(
                                        [
                                            {
                                                "type": "table",
                                                "attrs": {
                                                    "isNumberColumnEnabled": False,
                                                    "layout": "default"
                                                },
                                                "content": [
                                                    {
                                                        "type": "tableRow",
                                                        "content": [
                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Workstation Name"}]}]},
                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Workstation IP"}]}]}
                                                        ]
                                                    },
                                                    *[
                                                        {
                                                            "type": "tableRow",
                                                            "content": [
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": ws["host_name"]}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": ws["ip_address"]}]}]}
                                                            ]
                                                        }
                                                        for ws in workstations
                                                    ]
                                                ]
                                            }
                                        ] if workstations else [
                                            {
                                                "type": "paragraph",
                                                "content": [
                                                    {
                                                        "type": "text",
                                                        "text": "No workstation data available."
                                                    }
                                                ]
                                            }
                                        ]
                                    ),
                                    # Servers Summary section
                                    {
                                        "type": "paragraph",
                                        "content": [
                                            {
                                                "type": "text",
                                                "text": "Servers:"
                                            }
                                        ]
                                    },
                                    *(
                                        [
                                            {
                                                "type": "table",
                                                "attrs": {
                                                    "isNumberColumnEnabled": False,
                                                    "layout": "default"
                                                },
                                                "content": [
                                                    {
                                                        "type": "tableRow",
                                                        "content": [
                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Server Name"}]}]},
                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Server IP"}]}]}
                                                        ]
                                                    },
                                                    *[
                                                        {
                                                            "type": "tableRow",
                                                            "content": [
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": svr["host_name"]}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": svr["ip_address"]}]}]}
                                                            ]
                                                        }
                                                        for svr in servers
                                                    ]
                                                ]
                                            }
                                        ] if servers else [
                                            {
                                                "type": "paragraph",
                                                "content": [
                                                    {
                                                        "type": "text",
                                                        "text": "No server data available."
                                                    }
                                                ]
                                            }
                                        ]
                                    )
                                ]
                            },
                            "issuetype": {
                                "name": "Task"
                            },
                            "priority": {
                                "name": mapped_priority
                            },
                            "assignee": {
                                "name": "assignee_username"
                            },
                            "labels": [
                                "vulnerability",
                                "security"
                            ]
                        }
                    }




                    headers = {
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {jira_key}"
                    }


                    try:
                        response = requests.post(jira_url, data=json.dumps(combined_data), headers=headers, auth=HTTPBasicAuth(username, password))
                        if response.status_code == 201:

                            ticket_data = response.json()
                            checkVulIdExists = TicketingServiceDetails.objects.filter(cVulId=([key for key, value in TICKET_REFERENCE_CHOICES if value == 'JIRA'][0] + "-" +str(vul_id))).exists()
                            if not checkVulIdExists:
                                TicketingServiceDetails.objects.create(
                                        exploitsList = exploitIdList ,
                                        patchesList = patchesIdList,
                                        organizationId=organization_id,
                                        sq1VulId = vul_id,
                                        ticketId=int(((response.json())['key']).split('-')[1]),
                                        cVulId = [key for key, value in TICKET_REFERENCE_CHOICES if value == 'JIRA'][0] + "-" +str(vul_id),
                                        ticketServicePlatform=[key for key, value in TICKET_TYPE_CHOICES if value == 'JIRA'][0],
                                    )
                            else:
                                issue_key=int(((response.json())['key']).split('-')[1])
                                delete_response = requests.delete(f'{jira_url}{issue_key}', auth=HTTPBasicAuth(username, password))
                                if delete_response.status_code == 204:
                                    print(f"duplicate issue {issue_key} got deleted")

                    except requests.exceptions.HTTPError as http_err:
                        print(f"HTTP error occurred: {http_err}")
                    except requests.exceptions.ConnectionError as conn_err:
                        print(f"Connection error occurred: {conn_err}")
                    except requests.exceptions.Timeout as timeout_err:
                        print(f"Timeout error occurred: {timeout_err}")
                    except requests.exceptions.RequestException as req_err:
                        print(f"An error occurred: {req_err}")
                    else:
                        print(f"Success! Response status code: {response.status_code}")
                        print(f"Response content: {response.content}")

                return JsonResponse({
                    "status":"Success",
                    "message":"Issues created successfully"
                }, status=200)
            
            else:
                latest_existing_id = int((existing_vul_ids.last().cVulId).split('-')[1])

                if results[-1]["id"] == latest_existing_id:
                    return JsonResponse({"status":"No new vulnerabilities","message": "Nothing to add"}, status=200)
                
                elif results[-1]["id"] > latest_existing_id:
                    results = [vul for vul in results if vul["id"] > latest_existing_id]

                    for result in results:
                        vul_id = result.get("id")
                        organization_id = result.get("organization_id")

                        if vul_id not in existing_vul_ids:

                            cursor.execute("""
                            SELECT assetable_type, assetable_id
                            FROM assetables
                            WHERE vulnerabilities_id = %s
                        """, (vul_id,))
                        assetables_results = cursor.fetchall()

                        assets = {
                            "servers": [],
                            "workstations": []
                        }
                        ass_type = []
                        for i in assetables_results:
                            ass_type.append(i['assetable_type'])

                        ass_id = []
                        for i in assetables_results:
                            ass_id.append(i['assetable_id'])
                        
                        index = 0
                        for i in ass_type:
                            j = ass_id[index]
                            if i == 'App\\Models\\Workstations':
                                cursor.execute("""
                                SELECT host_name, ip_address
                                FROM workstations
                                WHERE id = %s AND organization_id = %s
                                """, (j, organization_id))
                                workstation = cursor.fetchone()
                                if workstation:
                                    assets["workstations"].append(workstation)
                                index = index+1
                            
        
                            if i == 'App\\Models\\Servers':
                                cursor.execute("""
                                SELECT host_name, ip_address
                                FROM workstations
                                WHERE id = %s AND organization_id = %s
                                """, (j, organization_id))
                                server = cursor.fetchone()
                                if server:
                                    assets["servers"].append(server)
                                index = index+1

                        mapped_priority = None

                        risk = float(result.get("risk"))

                        if 9.0 <= risk <= 10.0:
                            mapped_priority = "Highest"
                        elif 7.0 <= risk <= 8.9:
                            mapped_priority = "High"
                        elif 4.0 <= risk <= 6.9:
                            mapped_priority = "Medium"
                        elif 0.1 <= risk <= 3.9:
                            mapped_priority = "Low"

                        cursor.execute("SELECT * FROM exploits WHERE vul_id = %s AND organization_id = %s", (vul_id, organization_id))
                        exploits = cursor.fetchall()
                        exploitIdList = []
                        if exploits !=[]:
                            for exploit in exploits:
                                exploitIdList.append(exploit.get("id"))

                        cursor.execute("SELECT * FROM patch WHERE vul_id = %s", (vul_id,))
                        patches = cursor.fetchall()
                        patchesIdList = []
                        if patches !=[]:
                            for patch in patches:
                                patchesIdList.append(patch.get("id"))

                        cursor.execute("SELECT * FROM ticketing_tool WHERE organization_id = %s AND type = 'Jira'", (organization_id,))
                        ticketing_tool = cursor.fetchone()

                        if not ticketing_tool:
                            continue

                        jira_url = (json.loads(ticketing_tool.get("values"))).get('url')+"/rest/api/3/issue/"
                        jira_key =(json.loads(ticketing_tool.get("values"))).get('password')
                        boardName = (json.loads(ticketing_tool.get("values"))).get('board')


                        resultCVEs = json.loads(result.get("CVEs", {}))
                        if isinstance(resultCVEs, dict):
                            cve_list = resultCVEs.get("cves", [])
                        else:
                            cve_list = []
                        cve_string = ", ".join(cve_list)
                        context = {
                            'result': {
                                'CVEs': cve_string,
                                'severity': result.get('severity'),
                                'first_seen': result.get('first_seen'),
                                'last_identified_on': result.get('last_identified_on'),
                                'patch_priority': result.get('patch_priority'),
                            }
                        }

                        if patches:
                            patch_data = []
                            for patch in patches:
                                patchSolution = patch.get("solution", "")
                                patchDescription = patch.get("description", "")
                                patchComplexity = patch.get("complexity", "")
                                patchType = patch.get("type", "")
                                os_list = json.loads(patch.get("os", "[]"))
                                patchOs = ", ".join(f"{os['os_name']}-{os['os_version']}" for os in os_list)

                                patch_data.append({
                                    'solution': patchSolution,
                                    'description': patchDescription,
                                    'complexity': patchComplexity,
                                    'type': patchType,
                                    'os': patchOs,
                                    'url': patch.get("url", "")
                                })

                            patchContext = {
                                'patches': patch_data
                            }
                        else:
                            patchContext = {
                                'patches': []
                            }

                        remediationObj = {
                            "solution_patch": result["solution_patch"],
                            "solution_workaround": result["solution_workaround"],
                            "preventive_measure": result["preventive_measure"],
                            }
                        cves = json.loads(result["CVEs"])
                        cves_string = ", ".join(cves["cves"])
                        detectionSummaryObj = {
                            "CVE": cves_string,
                            "Severity": result["severity"],
                            "first_identified_on": result["first_seen"],
                            "last_identifies_on":result["last_identified_on"],
                            "severity":result["severity"],
                            "patch_priority":result["patch_priority"]
                            }
                        
                        vulnerability_description = None
                        if result['description'] is not None:
                            vulnerability_description = re.sub(r'\s+', ' ', re.sub(r'<.*?>', '', "Vulnerability synopsis: "+ result['description'])).strip()
                        else:
                            vulnerability_description = "Vulnerability synopsis: Description not aded"

                        workstations = assets['workstations']

                        def convert_none_workstations(data):
                            for workstation in workstations:
                                for key, value in workstation.items():
                                    if value is None:
                                        workstation[key]="NA"
                            return data

                        workstations = convert_none_workstations(workstations)

                        servers = assets['servers']

                        def convert_none_servers(data):
                            for server in servers:
                                for key, value in server.items():
                                    if value is None:
                                        server[key]="NA"
                            return data

                        servers = convert_none_servers(servers)

                        listOfDetection = [detectionSummaryObj]

                        def convert_datetime_to_string(data):
                            for item in data:
                                for key, value in item.items():
                                    if isinstance(value, datetime):
                                        item[key] = value.strftime('%Y-%m-%d %H:%M:%S')
                            return data
                        
                        listOfDetection = convert_datetime_to_string(listOfDetection)

                        for detection in listOfDetection:
                            for key, value in detection.items():
                                if value is None:
                                    detection[key] = "NA"

                        listOfRemediation = [remediationObj]

                        def convert_none(data):
                            for remediation in listOfRemediation:
                                for key, value in remediation.items():
                                    if value is None:
                                        remediation[key]="NA"
                            return data

                        listOfRemediation = convert_none(listOfRemediation)

                        allExploits = exploits
                        

                        def convert_none_for_exploits(data):
                            for exploit in allExploits:
                                for key, value in exploit.items():
                                    if value is None:
                                        exploit[key]="NA"
                            return data
                        allExploits = convert_none_for_exploits(allExploits)
                        allExploits = [{**exploit, 'dependency': 'Dependent on other exploits' if exploit['dependency'] == 'yes' else 'Self exploitable'} for exploit in allExploits]

                        allPatches = [
                            {
                                **patch,
                                'os': ', '.join([f"{os['os_name']}-{os['os_version']}" for os in json.loads(patch['os'])])
                            } for patch in patches
                        ]


                        def convert_none_for_patches(data):
                            for patch in allPatches:
                                for key, value in patch.items():
                                    if value is None:
                                        patch[key]="NA"
                            return data
                        allPatches = convert_none_for_patches(allPatches)
                        
                        username = (json.loads(ticketing_tool.get("values"))).get('username')
                        password = jira_key

                        combined_data = {
                            "fields": {
                                "project": {
                                    "key":boardName
                                },
                                "summary": result['name'],
                                "description": {
                                    "version": 1,
                                    "type": "doc",
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": vulnerability_description
                                                }
                                            ]
                                        },
                                        # Detection Summary section
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": "Detection Summary:"
                                                }
                                            ]
                                        },
                                        *(
                                            [
                                                {
                                                    "type": "table",
                                                    "attrs": {
                                                        "isNumberColumnEnabled": False,
                                                        "layout": "default"
                                                    },
                                                    "content": [
                                                        {
                                                            "type": "tableRow",
                                                            "content": [
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "CVE"}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "First Identified On"}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Severity"}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Last Identified On"}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Patch Priority"}]}]}
                                                            ]
                                                        },
                                                        *[
                                                            {
                                                                "type": "tableRow",
                                                                "content": [
                                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": det["CVE"]}]}]},
                                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": det["first_identified_on"]}]}]},
                                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": det["Severity"]}]}]},
                                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": det["last_identifies_on"]}]}]},
                                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": det["patch_priority"]}]}]}
                                                                ]
                                                            }
                                                            for det in listOfDetection
                                                        ]
                                                    ]
                                                }
                                            ] if listOfDetection else [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "No detection data available."
                                                        }
                                                    ]
                                                }
                                            ]
                                        ),
                                        # Remediation Summary section
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": "Remediation:"
                                                }
                                            ]
                                        },
                                        *(
                                            [
                                                {
                                                    "type": "table",
                                                    "attrs": {
                                                        "isNumberColumnEnabled": False,
                                                        "layout": "default"
                                                    },
                                                    "content": [
                                                        {
                                                            "type": "tableRow",
                                                            "content": [
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Solution Patch"}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Solution Workaround"}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Preventive Measure"}]}]}
                                                            ]
                                                        },
                                                        *[
                                                            {
                                                                "type": "tableRow",
                                                                "content": [
                                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": rem["solution_patch"]}]}]},
                                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": rem["solution_workaround"]}]}]},
                                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": rem["preventive_measure"]}]}]}
                                                                ]
                                                            }
                                                            for rem in listOfRemediation
                                                        ]
                                                    ]
                                                }
                                            ] if listOfRemediation else [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "No remediation data available."
                                                        }
                                                    ]
                                                }
                                            ]
                                        ),
                                        # Exploits Summary section
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": "Exploits Table:"
                                                }
                                            ]
                                        },
                                        *(
                                            [
                                                {
                                                    "type": "table",
                                                    "attrs": {
                                                        "isNumberColumnEnabled": False,
                                                        "layout": "default"
                                                    },
                                                    "content": [
                                                        {
                                                            "type": "tableRow",
                                                            "content": [
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Exploit Name"}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Description"}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Complexity"}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Dependency"}]}]}
                                                            ]
                                                        },
                                                        *[
                                                            {
                                                                "type": "tableRow",
                                                                "content": [
                                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": exp["name"]}]}]},
                                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": exp["description"]}]}]},
                                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": exp["complexity"]}]}]},
                                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": exp["dependency"]}]}]}
                                                                ]
                                                            }
                                                            for exp in allExploits
                                                        ]
                                                    ]
                                                }
                                            ] if allExploits else [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "No exploit data available."
                                                        }
                                                    ]
                                                }
                                            ]
                                        ),
                                        # Patch Summary section
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": "Patch(es):"
                                                }
                                            ]
                                        },
                                        *(
                                            [
                                                {
                                                    "type": "table",
                                                    "attrs": {
                                                        "isNumberColumnEnabled": False,
                                                        "layout": "default"
                                                    },
                                                    "content": [
                                                        {
                                                            "type": "tableRow",
                                                            "content": [
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Patch Solution"}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Description"}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Complexity"}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "URL"}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Type"}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "OS"}]}]}
                                                            ]
                                                        },
                                                        *[
                                                            {
                                                                "type": "tableRow",
                                                                "content": [
                                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": patch["solution"]}]}]},
                                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": patch["description"]}]}]},
                                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": patch["complexity"]}]}]},
                                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": patch["url"]}]}]},
                                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": patch["type"]}]}]},
                                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": patch["os"]}]}]}
                                                                ]
                                                            }
                                                            for patch in allPatches
                                                        ]
                                                    ]
                                                }
                                            ] if allPatches else [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "No patch data available."
                                                        }
                                                    ]
                                                }
                                            ]
                                        ),
                                        # Workstations Summary section
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": "Workstations:"
                                                }
                                            ]
                                        },
                                        *(
                                            [
                                                {
                                                    "type": "table",
                                                    "attrs": {
                                                        "isNumberColumnEnabled": False,
                                                        "layout": "default"
                                                    },
                                                    "content": [
                                                        {
                                                            "type": "tableRow",
                                                            "content": [
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Workstation Name"}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Workstation IP"}]}]}
                                                            ]
                                                        },
                                                        *[
                                                            {
                                                                "type": "tableRow",
                                                                "content": [
                                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": ws["host_name"]}]}]},
                                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": ws["ip_address"]}]}]}
                                                                ]
                                                            }
                                                            for ws in workstations
                                                        ]
                                                    ]
                                                }
                                            ] if workstations else [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "No workstation data available."
                                                        }
                                                    ]
                                                }
                                            ]
                                        ),
                                        # Servers Summary section
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": "Servers:"
                                                }
                                            ]
                                        },
                                        *(
                                            [
                                                {
                                                    "type": "table",
                                                    "attrs": {
                                                        "isNumberColumnEnabled": False,
                                                        "layout": "default"
                                                    },
                                                    "content": [
                                                        {
                                                            "type": "tableRow",
                                                            "content": [
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Server Name"}]}]},
                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Server IP"}]}]}
                                                            ]
                                                        },
                                                        *[
                                                            {
                                                                "type": "tableRow",
                                                                "content": [
                                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": svr["host_name"]}]}]},
                                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": svr["ip_address"]}]}]}
                                                                ]
                                                            }
                                                            for svr in servers
                                                        ]
                                                    ]
                                                }
                                            ] if servers else [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": "No server data available."
                                                        }
                                                    ]
                                                }
                                            ]
                                        )
                                    ]
                                },
                                "issuetype": {
                                    "name": "Task"
                                },
                                "priority": {
                                "name": "High"
                                },
                                "assignee": {
                                    "name": "assignee_username"
                                },
                                "labels": [
                                    "vulnerability",
                                    "security"
                                ]
                            }
                        }




                        headers = {
                            "Content-Type": "application/json",
                            "Authorization": f"Bearer {jira_key}"
                        }


                        try:
                            response = requests.post(jira_url, data=json.dumps(combined_data), headers=headers, auth=HTTPBasicAuth(username, password))
                            if response.status_code == 201:

                                ticket_data = response.json()
                                checkVulIdExists =TicketingServiceDetails.objects.filter(cVulId=([key for key, value in TICKET_REFERENCE_CHOICES if value == 'JIRA'][0] + "-" +str(vul_id))).exists()
                                if not checkVulIdExists:
                                    TicketingServiceDetails.objects.create(
                                            exploitsList = exploitIdList ,
                                            patchesList = patchesIdList,
                                            organizationId=organization_id,
                                            sq1VulId = vul_id,
                                            ticketId=int(((response.json())['key']).split('-')[1]),
                                            cVulId = [key for key, value in TICKET_REFERENCE_CHOICES if value == 'JIRA'][0] + "-" +str(vul_id),
                                            ticketServicePlatform=[key for key, value in TICKET_TYPE_CHOICES if value == 'JIRA'][0],
                                        )
                                else:
                                    issue_key=int(((response.json())['key']).split('-')[1])
                                    delete_response = requests.delete(f'{jira_url}{issue_key}', auth=HTTPBasicAuth(username, password))
                                    if delete_response.status_code == 204:
                                        print(f"duplicate issue {issue_key} got deleted")

                        except requests.exceptions.HTTPError as http_err:
                            print(f"HTTP error occurred: {http_err}")
                        except requests.exceptions.ConnectionError as conn_err:
                            print(f"Connection error occurred: {conn_err}")
                        except requests.exceptions.Timeout as timeout_err:
                            print(f"Timeout error occurred: {timeout_err}")
                        except requests.exceptions.RequestException as req_err:
                            print(f"An error occurred: {req_err}")
                        else:
                            print(f"Success! Response status code: {response.status_code}")
                            print(f"Response content: {response.content}")

                    return JsonResponse({
                    "status":"Success",
                    "message":"New issues created successfully"
                }, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

    finally:
        if connection.is_connected():
            connection.close()
    

def updateExploitsAndPatchesForJira():
    try:
        connection = get_connection()
        if not connection or not connection.is_connected():
            return JsonResponse({"error": "Failed to connect to the database"}, status=500)

        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM ticketing_tool WHERE type = 'JIRA'")
            ticketing_tools = cursor.fetchall()

            if not ticketing_tools:
                return JsonResponse({"status": "No JIRA tools found"}, status=404)

            all_tickets = []

            for tool in ticketing_tools:
                url = ((json.loads(tool.get("values"))).get('url')) + "/rest/api/3/search"
                key = (json.loads(tool.get("values"))).get('password')
                boardName = (json.loads(tool.get("values"))).get('board')

                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {key}"
                }

                try:
                    username = (json.loads(tool.get("values"))).get('username')
                    password = key
                    params = {
                        "maxResults": 1000
                    }
                    response = requests.get(url, headers=headers, auth=HTTPBasicAuth(username, password), params=params)

                    if response.status_code == 200:
                        for issue in response.json()['issues']:
                            issue_key = issue.get("key")
                            issueId = int((issue.get("key").split('-')[1]))
                            checkIssueIdInTicketingService = TicketingServiceDetails.objects.filter(ticketId=issueId).exists()

                            if checkIssueIdInTicketingService:
                                ticketObj = TicketingServiceDetails.objects.get(ticketId=issueId)
                                vulnerabilityId = ticketObj.sq1VulId
                                print(vulnerabilityId)
                                organizationId = ticketObj.organizationId

                                exploitsList = ast.literal_eval(ticketObj.exploitsList)
                                patchesList = ast.literal_eval(ticketObj.patchesList)

                                cursor.execute(f"SELECT * FROM exploits WHERE vul_id = {vulnerabilityId}")
                                exploits = cursor.fetchall()

                                cursor.execute(f"SELECT * FROM patch WHERE vul_id = {vulnerabilityId}")
                                patches = cursor.fetchall()

                                cursor.execute(f"SELECT * FROM vulnerabilities WHERE id = {vulnerabilityId}")
                                vulnerabilityResult = cursor.fetchall()

                                if not vulnerabilityResult:
                                    continue

                                if len(patches) > len(patchesList) or len(exploits) > len(exploitsList):
                                    vulnerability_name = vulnerabilityResult[0]['name'] if vulnerabilityResult[0]['name'] is not None else "Description not added"

                                    vulnerability_description =None
                                    if vulnerabilityResult[0]['description'] is not None:
                                        vulnerability_description = re.sub(r'\s+', ' ', re.sub(r'<.*?>', '', vulnerabilityResult[0]['description'])).strip()
                                    else:
                                        vulnerability_description = "Vulnerability synopsis: Description not aded"     
                                    mapped_priority = None 

                                    risk = float(vulnerabilityResult[0].get("risk"))

                                    if 9.0 <= risk <= 10.0:
                                        mapped_priority = "Highest"
                                    elif 7.0 <= risk <= 8.9:
                                        mapped_priority = "High"
                                    elif 4.0 <= risk <= 6.9:
                                        mapped_priority = "Medium"
                                    elif 0.1 <= risk <= 3.9:
                                        mapped_priority = "Low"

                                    # Detection Summary
                                    cves = json.loads(vulnerabilityResult[0]["CVEs"])
                                    cves_string = ", ".join(cves["cves"])
                                    detectionSummaryObj = {
                                        "CVE": cves_string,
                                        "Severity": vulnerabilityResult[0]["severity"],
                                        "first_identified_on": vulnerabilityResult[0]["first_seen"],
                                        "last_identifies_on":vulnerabilityResult[0]["last_identified_on"],
                                        "patch_priority":vulnerabilityResult[0]["patch_priority"]
                                        }
                                    listOfDetection = [detectionSummaryObj]

                                    def convert_datetime_to_string(data):
                                        for item in data:
                                            for key, value in item.items():
                                                if isinstance(value, datetime):
                                                    item[key] = value.strftime('%Y-%m-%d %H:%M:%S')
                                        return data
                                    
                                    listOfDetection = convert_datetime_to_string(listOfDetection)

                                    for detection in listOfDetection:
                                        for key, value in detection.items():
                                            if value is None:
                                                detection[key] = "NA"

                                    # Remediation Summary
                                    remediationObj = {
                                            "solution_patch": vulnerabilityResult[0]["solution_patch"],
                                            "solution_workaround": vulnerabilityResult[0]["solution_workaround"],
                                            "preventive_measure": vulnerabilityResult[0]["preventive_measure"],
                                            }
                                    listOfRemediation = [remediationObj]

                                    def convert_none(data):
                                        for remediation in listOfRemediation:
                                            for key, value in remediation.items():
                                                if value is None:
                                                    remediation[key]="NA"
                                        return data

                                    listOfRemediation = convert_none(listOfRemediation)
                                    

                                    # workstations and servers
                                    cursor.execute("""
                                    SELECT assetable_type, assetable_id
                                    FROM assetables
                                    WHERE vulnerabilities_id = %s
                                    """, (vulnerabilityId,))
                                    assetables_results = cursor.fetchall()

                                    assets = {
                                        "servers": [],
                                        "workstations": []
                                    }
                                    ass_type = []
                                    for i in assetables_results:
                                        ass_type.append(i['assetable_type'])

                                    ass_id = []
                                    for i in assetables_results:
                                        ass_id.append(i['assetable_id'])

                                    index = 0
                                    for i in ass_type:
                                        j = ass_id[index]
                                        if i == 'App\\Models\\Workstations':
                                            cursor.execute("""
                                            SELECT host_name, ip_address
                                            FROM workstations
                                            WHERE id = %s AND organization_id = %s
                                            """, (j, organizationId))
                                            workstation = cursor.fetchone()
                                            if workstation:
                                                assets["workstations"].append(workstation)
                                            index = index+1
                                        

                                        if i == 'App\\Models\\Servers':
                                            cursor.execute("""
                                            SELECT host_name, ip_address
                                            FROM workstations
                                            WHERE id = %s AND organization_id = %s
                                            """, (j, organizationId))
                                            server = cursor.fetchone()
                                            if server:
                                                assets["servers"].append(server)
                                            index = index+1
                                    
                                    workstations = assets['workstations']

                                    def convert_none_workstations(data):
                                        for workstation in workstations:
                                            for key, value in workstation.items():
                                                if value is None:
                                                    workstation[key]="NA"
                                        return data

                                    workstations = convert_none_workstations(workstations)

                                    servers = assets['servers']

                                    def convert_none_servers(data):
                                        for server in servers:
                                            for key, value in server.items():
                                                if value is None:
                                                    server[key]="NA"
                                        return data

                                    servers = convert_none_servers(servers)

                                    # exploits and patches

                                    allExploits = exploits
                                    def convert_none_for_exploits(data):
                                        for exploit in allExploits:
                                            for key, value in exploit.items():
                                                if value is None:
                                                    exploit[key]="NA"
                                        return data
                                    allExploits = convert_none_for_exploits(allExploits)
                                    allExploits = [{**exploit, 'dependency': 'Dependent on other exploits' if exploit['dependency'] == 'yes' else 'Self exploitable'} for exploit in allExploits]

                                    allPatches = [
                                        {
                                            **patch,
                                            'os': ', '.join([f"{os['os_name']}-{os['os_version']}" for os in json.loads(patch['os'])])
                                        } for patch in patches
                                    ]


                                    def convert_none_for_patches(data):
                                        for patch in allPatches:
                                            for key, value in patch.items():
                                                if value is None:
                                                    patch[key]="NA"
                                        return data
                                    allPatches = convert_none_for_patches(allPatches)
                                    combined_data = {
                                        "fields": {
                                            "project": {
                                                "key":boardName
                                            },
                                            "summary": vulnerability_name,
                                            "description": {
                                                "version": 1,
                                                "type": "doc",
                                                "content": [
                                                    {
                                                        "type": "paragraph",
                                                        "content": [
                                                            {
                                                                "type": "text",
                                                                "text": vulnerability_description
                                                            }
                                                        ]
                                                    },
                                                    # Detection Summary section
                                                    {
                                                        "type": "paragraph",
                                                        "content": [
                                                            {
                                                                "type": "text",
                                                                "text": "Detection Summary:"
                                                            }
                                                        ]
                                                    },
                                                    *(
                                                        [
                                                            {
                                                                "type": "table",
                                                                "attrs": {
                                                                    "isNumberColumnEnabled": False,
                                                                    "layout": "default"
                                                                },
                                                                "content": [
                                                                    {
                                                                        "type": "tableRow",
                                                                        "content": [
                                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "CVE"}]}]},
                                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "First Identified On"}]}]},
                                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Last Identified On"}]}]},
                                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Patch Priority"}]}]}
                                                                        ]
                                                                    },
                                                                    *[
                                                                        {
                                                                            "type": "tableRow",
                                                                            "content": [
                                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": det["CVE"]}]}]},
                                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": det["first_identified_on"]}]}]},
                                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": det["last_identifies_on"]}]}]},
                                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": det["patch_priority"]}]}]}
                                                                            ]
                                                                        }
                                                                        for det in listOfDetection
                                                                    ]
                                                                ]
                                                            }
                                                        ] if listOfDetection else [
                                                            {
                                                                "type": "paragraph",
                                                                "content": [
                                                                    {
                                                                        "type": "text",
                                                                        "text": "No detection data available."
                                                                    }
                                                                ]
                                                            }
                                                        ]
                                                    ),
                                                    # Remediation Summary section
                                                    {
                                                        "type": "paragraph",
                                                        "content": [
                                                            {
                                                                "type": "text",
                                                                "text": "Remediation:"
                                                            }
                                                        ]
                                                    },
                                                    *(
                                                        [
                                                            {
                                                                "type": "table",
                                                                "attrs": {
                                                                    "isNumberColumnEnabled": False,
                                                                    "layout": "default"
                                                                },
                                                                "content": [
                                                                    {
                                                                        "type": "tableRow",
                                                                        "content": [
                                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Solution Patch"}]}]},
                                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Solution Workaround"}]}]},
                                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Preventive Measure"}]}]}
                                                                        ]
                                                                    },
                                                                    *[
                                                                        {
                                                                            "type": "tableRow",
                                                                            "content": [
                                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": rem["solution_patch"]}]}]},
                                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": rem["solution_workaround"]}]}]},
                                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": rem["preventive_measure"]}]}]}
                                                                            ]
                                                                        }
                                                                        for rem in listOfRemediation
                                                                    ]
                                                                ]
                                                            }
                                                        ] if listOfRemediation else [
                                                            {
                                                                "type": "paragraph",
                                                                "content": [
                                                                    {
                                                                        "type": "text",
                                                                        "text": "No remediation data available."
                                                                    }
                                                                ]
                                                            }
                                                        ]
                                                    ),
                                                    # Exploits Summary section
                                                    {
                                                        "type": "paragraph",
                                                        "content": [
                                                            {
                                                                "type": "text",
                                                                "text": "Exploits Table:"
                                                            }
                                                        ]
                                                    },
                                                    *(
                                                        [
                                                            {
                                                                "type": "table",
                                                                "attrs": {
                                                                    "isNumberColumnEnabled": False,
                                                                    "layout": "default"
                                                                },
                                                                "content": [
                                                                    {
                                                                        "type": "tableRow",
                                                                        "content": [
                                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Exploit Name"}]}]},
                                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Description"}]}]},
                                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Complexity"}]}]},
                                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Dependency"}]}]}
                                                                        ]
                                                                    },
                                                                    *[
                                                                        {
                                                                            "type": "tableRow",
                                                                            "content": [
                                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": exp["name"]}]}]},
                                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": exp["description"]}]}]},
                                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": exp["complexity"]}]}]},
                                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": exp["dependency"]}]}]}
                                                                            ]
                                                                        }
                                                                        for exp in allExploits
                                                                    ]
                                                                ]
                                                            }
                                                        ] if allExploits else [
                                                            {
                                                                "type": "paragraph",
                                                                "content": [
                                                                    {
                                                                        "type": "text",
                                                                        "text": "No exploit data available."
                                                                    }
                                                                ]
                                                            }
                                                        ]
                                                    ),
                                                    # Patch Summary section
                                                    {
                                                        "type": "paragraph",
                                                        "content": [
                                                            {
                                                                "type": "text",
                                                                "text": "Patch(es):"
                                                            }
                                                        ]
                                                    },
                                                    *(
                                                        [
                                                            {
                                                                "type": "table",
                                                                "attrs": {
                                                                    "isNumberColumnEnabled": False,
                                                                    "layout": "default"
                                                                },
                                                                "content": [
                                                                    {
                                                                        "type": "tableRow",
                                                                        "content": [
                                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Patch Solution"}]}]},
                                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Description"}]}]},
                                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Complexity"}]}]},
                                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "URL"}]}]},
                                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Type"}]}]},
                                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "OS"}]}]}
                                                                        ]
                                                                    },
                                                                    *[
                                                                        {
                                                                            "type": "tableRow",
                                                                            "content": [
                                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": patch["solution"]}]}]},
                                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": patch["description"]}]}]},
                                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": patch["complexity"]}]}]},
                                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": patch["url"]}]}]},
                                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": patch["type"]}]}]},
                                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": patch["os"]}]}]}
                                                                            ]
                                                                        }
                                                                        for patch in allPatches
                                                                    ]
                                                                ]
                                                            }
                                                        ] if allPatches else [
                                                            {
                                                                "type": "paragraph",
                                                                "content": [
                                                                    {
                                                                        "type": "text",
                                                                        "text": "No patch data available."
                                                                    }
                                                                ]
                                                            }
                                                        ]
                                                    ),
                                                    # Workstations Summary section
                                                    {
                                                        "type": "paragraph",
                                                        "content": [
                                                            {
                                                                "type": "text",
                                                                "text": "Workstations:"
                                                            }
                                                        ]
                                                    },
                                                    *(
                                                        [
                                                            {
                                                                "type": "table",
                                                                "attrs": {
                                                                    "isNumberColumnEnabled": False,
                                                                    "layout": "default"
                                                                },
                                                                "content": [
                                                                    {
                                                                        "type": "tableRow",
                                                                        "content": [
                                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Workstation Name"}]}]},
                                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Workstation IP"}]}]}
                                                                        ]
                                                                    },
                                                                    *[
                                                                        {
                                                                            "type": "tableRow",
                                                                            "content": [
                                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": ws["host_name"]}]}]},
                                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": ws["ip_address"]}]}]}
                                                                            ]
                                                                        }
                                                                        for ws in workstations
                                                                    ]
                                                                ]
                                                            }
                                                        ] if workstations else [
                                                            {
                                                                "type": "paragraph",
                                                                "content": [
                                                                    {
                                                                        "type": "text",
                                                                        "text": "No workstation data available."
                                                                    }
                                                                ]
                                                            }
                                                        ]
                                                    ),
                                                    # Servers Summary section
                                                    {
                                                        "type": "paragraph",
                                                        "content": [
                                                            {
                                                                "type": "text",
                                                                "text": "Servers:"
                                                            }
                                                        ]
                                                    },
                                                    *(
                                                        [
                                                            {
                                                                "type": "table",
                                                                "attrs": {
                                                                    "isNumberColumnEnabled": False,
                                                                    "layout": "default"
                                                                },
                                                                "content": [
                                                                    {
                                                                        "type": "tableRow",
                                                                        "content": [
                                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Server Name"}]}]},
                                                                            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Server IP"}]}]}
                                                                        ]
                                                                    },
                                                                    *[
                                                                        {
                                                                            "type": "tableRow",
                                                                            "content": [
                                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": svr["host_name"]}]}]},
                                                                                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": svr["ip_address"]}]}]}
                                                                            ]
                                                                        }
                                                                        for svr in servers
                                                                    ]
                                                                ]
                                                            }
                                                        ] if servers else [
                                                            {
                                                                "type": "paragraph",
                                                                "content": [
                                                                    {
                                                                        "type": "text",
                                                                        "text": "No server data available."
                                                                    }
                                                                ]
                                                            }
                                                        ]
                                                    )
                                                ]
                                            },
                                            "issuetype": {
                                                "name": "Task"
                                            },
                                            "priority": {
                                                "name": mapped_priority
                                            },
                                            "assignee": {
                                                "name": "assignee_username"
                                            },
                                            "labels": [
                                                "vulnerability",
                                                "security"
                                            ]
                                        }
                                    }


                                    patchUrl = (json.loads(tool.get("values"))).get("url") + f"/rest/api/3/issue/{issue_key}"
                                    response = requests.put(patchUrl,
                                                            data=json.dumps(combined_data),
                                                            headers=headers,
                                                            auth=HTTPBasicAuth(username, password))

                                    if response.status_code == 204:
                                        newPatchIds = [patch['id'] for patch in patches if patch['id'] not in patchesList]
                                        if newPatchIds:
                                            ticket_service_details = TicketingServiceDetails.objects.get(sq1VulId=vulnerabilityId, ticketServicePlatform='jira')
                                            existingPatchIds = ast.literal_eval(ticket_service_details.patchesList or '[]')
                                            newPatchesList = existingPatchIds + newPatchIds
                                            ticket_service_details.patchesList = str(newPatchesList)
                                            ticket_service_details.save()

                                        newExploitIds = [exploit['id'] for exploit in exploits if exploit['id'] not in exploitsList]
                                        if newExploitIds:
                                            ticket_service_details = TicketingServiceDetails.objects.get(sq1VulId=vulnerabilityId, ticketServicePlatform='jira')
                                            existingExploitIds = ast.literal_eval(ticket_service_details.exploitsList or '[]')
                                            newExploitsList = existingExploitIds + newExploitIds
                                            ticket_service_details.exploitsList = str(newExploitsList)
                                            ticket_service_details.save()

                                else:
                                    continue
                        else:
                            return JsonResponse({"status": "Success", "message": "exploits and patches updated successfully"}, status=200)

                    else:
                        return JsonResponse({"error": "Failed to fetch JIRA issues", "status_code": response.status_code}, status=500)

                except requests.exceptions.RequestException as e:
                    return JsonResponse({"error": "Error communicating with JIRA", "message": str(e)}, status=500)

        return JsonResponse({"status": "Success", "message": "Exploits and patches updated for the respective tickets"}, status=200)

    except Exception as e:
        return JsonResponse({"error": "An error occurred", "message": str(e)}, status=500)
           
def changeVulnerabilityStatusForFreshService():
    connection = get_connection()
    
    if not connection or not connection.is_connected():
        return JsonResponse({"error": "Failed to connect to the database"}, status=500)
    
    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM ticketing_tool WHERE type = 'Freshservice'")
            ticketing_tools = cursor.fetchall()

            all_tickets = []

            for tool in ticketing_tools:
                url = (json.loads(tool.get("values"))).get("url")
                key = (json.loads(tool.get("values"))).get("key")

                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Basic {key}"
                }

                page = 1
                while True:
                    try:
                        params = {
                            "per_page": 100,
                            "page": page
                        }
                        response = requests.get(f"{url}/api/v2/tickets", headers=headers, params=params)

                        if response.status_code == 200:
                            tickets = response.json().get('tickets', [])
                            all_tickets.extend(tickets)
                            if not tickets:
                                break
                            for ticket in tickets:
                                ticket_id = ticket.get("id")

                                if ticket.get("status") == 5:
                                    try:
                                        ticket_details = TicketingServiceDetails.objects.get(ticketId=ticket_id)
                                        vulId = ticket_details.sq1VulId
                                        ticket_details.isActive = False
                                        ticket_details.save()

                                        cursor.execute("SELECT * FROM vulnerabilities")
                                        vulnerabilitiesInMainDB = cursor.fetchall()
                                        cursor.execute(f"UPDATE vulnerabilities SET status = '1' WHERE id = {vulId}")

                                        connection.commit()

                                    except TicketingServiceDetails.DoesNotExist:
                                        return JsonResponse({"error": f"TicketingServiceDetails not found for ticket ID: {ticket_id}"}, status=404)
                                    except Exception as e:
                                        return JsonResponse({"error": f"Error updating vulnerability for ticket ID {ticket_id}: {str(e)}"}, status=500)
                        else:
                            return JsonResponse({"error": f"Failed to fetch tickets from {url}: {response.status_code} - {response.text}"}, status=500)

                    except requests.RequestException as e:
                        return JsonResponse({"error": f"Request failed for {url}: {str(e)}"}, status=500)

                    page += 1

            if all_tickets:
                return JsonResponse({"message": "Tickets processed successfully", "processed_tickets": len(all_tickets)}, status=200)
            else:
                return JsonResponse({"message": "No tickets found"}, status=200)
    
    except Exception as e:
        return JsonResponse({"error": f"An error occurred: {str(e)}"}, status=500)
    
    finally:
        if connection.is_connected():
            connection.close()
          
logger = logging.getLogger(__name__)

def changeVulnerabilityStatusForJira():
    connection = get_connection()
    if not connection or not connection.is_connected():
        return JsonResponse({"error": "Failed to connect to the database"}, status=500)
    
    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM ticketing_tool WHERE type = 'JIRA'")
            ticketing_tools = cursor.fetchall()

            all_tickets = []

            for tool in ticketing_tools:
                url = (json.loads(tool.get("values"))).get("url")
                username = (json.loads(tool.get("values"))).get("username")
                password = (json.loads(tool.get("values"))).get("password")

                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {password}"
                }

                params = {
                    "startAt": 0,
                    "maxResults": 100
                }

                while True:
                    response = requests.get(f"{url}/rest/api/3/search", headers=headers, auth=HTTPBasicAuth(username, password), params=params)
                    
                    if response.status_code == 200:
                        data = response.json()
                        issues = data.get('issues', [])
                        
                        if not issues:
                            break 

                        for issue in issues:
                            issue_id = int(issue.get("key").split('-')[1])
                            
                            if TicketingServiceDetails.objects.filter(ticketId=issue_id).exists():
                                if issue.get("fields", {}).get("status", {}).get("name") == "Done":

                                    ticket_details = TicketingServiceDetails.objects.get(ticketId=issue_id)
                                    vul_id = ticket_details.sq1VulId

                                    ticket_details.isActive = True
                                    ticket_details.save()

                                    cursor.execute("SELECT * FROM vulnerabilities")
                                    vulnerabilitiesInMainDB = cursor.fetchall()
                                    cursor.execute(f"UPDATE vulnerabilities SET status = '1' WHERE id = {vul_id}")

                                    connection.commit()

                        params["startAt"] += params["maxResults"]

                    else:
                        logger.error(f"Failed to fetch issues from JIRA. Status code: {response.status_code}, Response: {response.text}")
                        break

    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        return JsonResponse({"error": str(e)}, status=500)
    
    finally:
        if connection.is_connected():
            connection.close()

    return JsonResponse({"success": "Vulnerability status updated successfully"})

def createCardInTrello():
    connection = get_connection()
    if not connection or not connection.is_connected():
        return JsonResponse({"error": "Failed to connect to the database"}, status=500)

    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM vulnerabilities;")
            results = cursor.fetchall()
            existing_vul_ids = TicketingServiceDetails.objects.filter(ticketServicePlatform="Trello")

            if len(existing_vul_ids) == 0:
                for result in results:
                    vul_id = result.get("id")
                    organization_id = result.get("organization_id")

                    if vul_id not in existing_vul_ids:

                        cursor.execute("""
                        SELECT assetable_type, assetable_id
                        FROM assetables
                        WHERE vulnerabilities_id = %s
                    """, (vul_id,))
                    assetables_results = cursor.fetchall()

                    assets = {
                        "servers": [],
                        "workstations": []
                    }
                    ass_type = []
                    for i in assetables_results:
                        ass_type.append(i['assetable_type'])

                    ass_id = []
                    for i in assetables_results:
                        ass_id.append(i['assetable_id'])
                    
                    index = 0
                    for i in ass_type:
                        j = ass_id[index]
                        if i == 'App\\Models\\Workstations':
                            cursor.execute("""
                            SELECT host_name, ip_address
                            FROM workstations
                            WHERE id = %s AND organization_id = %s
                            """, (j, organization_id))
                            workstation = cursor.fetchone()
                            if workstation:
                                assets["workstations"].append(workstation)
                            index = index+1
                        
    
                        if i == 'App\\Models\\Servers':
                            cursor.execute("""
                            SELECT host_name, ip_address
                            FROM workstations
                            WHERE id = %s AND organization_id = %s
                            """, (j, organization_id))
                            server = cursor.fetchone()
                            if server:
                                assets["servers"].append(server)
                            index = index+1

                    mapped_priority = None

                    risk = float(result.get("risk"))

                    if 9.0 <= risk <= 10.0:
                        mapped_priority = "Risk: Critical"
                    elif 7.0 <= risk <= 8.9:
                        mapped_priority = "Risk: High"
                    elif 4.0 <= risk <= 6.9:
                        mapped_priority = "Risk: Medium"
                    elif 0.1 <= risk <= 3.9:
                        mapped_priority = "Risk: Low"

                    cursor.execute("SELECT * FROM exploits WHERE vul_id = %s AND organization_id = %s", (vul_id, organization_id))
                    exploits = cursor.fetchall()
                    exploitIdList = []
                    if exploits !=[]:
                        for exploit in exploits:
                            exploitIdList.append(exploit.get("id"))

                    cursor.execute("SELECT * FROM patch WHERE vul_id = %s", (vul_id,))
                    patches = cursor.fetchall()
                    patchesIdList = []
                    if patches !=[]:
                        for patch in patches:
                            patchesIdList.append(patch.get("id"))

                    cursor.execute("SELECT * FROM ticketing_tool WHERE organization_id = %s AND type = 'Trello'", (organization_id,))
                    ticketing_tool = cursor.fetchone()

                    if not ticketing_tool:
                        continue

                    url = (json.loads(ticketing_tool.get("values"))).get("url") +"/1/cards"
                    trelloKey = (json.loads(ticketing_tool.get("values"))).get("key")
                    token = (json.loads(ticketing_tool.get("values"))).get("token")
                    listId =(json.loads(ticketing_tool.get("values"))).get("listid")

                    

                    


                    resultCVEs = json.loads(result.get("CVEs", {}))
                    if isinstance(resultCVEs, dict):
                        cve_list = resultCVEs.get("cves", [])
                    else:
                        cve_list = []
                    cve_string = ", ".join(cve_list)
                    context = {
                        'result': {
                            'CVEs': cve_string,
                            'severity': result.get('severity'),
                            'first_seen': result.get('first_seen'),
                            'last_identified_on': result.get('last_identified_on'),
                            'patch_priority': result.get('patch_priority'),
                        }
                    }

                    if patches:
                        patch_data = []
                        for patch in patches:
                            patchSolution = patch.get("solution", "")
                            patchDescription = patch.get("description", "")
                            patchComplexity = patch.get("complexity", "")
                            patchType = patch.get("type", "")
                            os_list = json.loads(patch.get("os", "[]"))
                            patchOs = ", ".join(f"{os['os_name']}-{os['os_version']}" for os in os_list)

                            patch_data.append({
                                'solution': patchSolution,
                                'description': patchDescription,
                                'complexity': patchComplexity,
                                'type': patchType,
                                'os': patchOs,
                                'url': patch.get("url", "")
                            })

                        patchContext = {
                            'patches': patch_data
                        }
                    else:
                        patchContext = {
                            'patches': []
                        }

                    remediationObj = {
                        "solution_patch": result["solution_patch"],
                        "solution_workaround": result["solution_workaround"],
                        "preventive_measure": result["preventive_measure"],
                        }
                    cves = json.loads(result["CVEs"])
                    cves_string = ", ".join(cves["cves"])
                    detectionSummaryObj = {
                        "CVE": cves_string,
                        "Severity": result["severity"],
                        "first_identified_on": result["first_seen"],
                        "last_identifies_on":result["last_identified_on"],
                        "patch_priority":result["patch_priority"]
                        }
                    
                    vulnerability_description = None
                    if result['description'] is not None:
                        vulnerability_description = re.sub(r'\s+', ' ', re.sub(r'<.*?>', '', "Vulnerability synopsis: "+ result['description'])).strip()
                    else:
                        vulnerability_description = "Vulnerability synopsis: Description not aded"


                    workstations = assets['workstations']

                    def convert_none_workstations(data):
                        for workstation in workstations:
                            for key, value in workstation.items():
                                if value is None:
                                    workstation[key]="NA"
                        return data

                    workstations = convert_none_workstations(workstations)

                    servers = assets['servers']

                    def convert_none_servers(data):
                        for server in servers:
                            for key, value in server.items():
                                if value is None:
                                    server[key]="NA"
                        return data

                    servers = convert_none_servers(servers)

                    listOfDetection = [detectionSummaryObj]

                    def convert_datetime_to_string(data):
                        for item in data:
                            for key, value in item.items():
                                if isinstance(value, datetime):
                                    item[key] = value.strftime('%Y-%m-%d %H:%M:%S')
                        return data
                    
                    listOfDetection = convert_datetime_to_string(listOfDetection)

                    for detection in listOfDetection:
                        for key, value in detection.items():
                            if value is None:
                                detection[key] = "NA"

                    listOfRemediation = [remediationObj]

                    def convert_none(data):
                        for remediation in listOfRemediation:
                            for key, value in remediation.items():
                                if value is None:
                                    remediation[key]="NA"
                        return data

                    listOfRemediation = convert_none(listOfRemediation)

                    allExploits = exploits
                    def convert_none_for_exploits(data):
                        for exploit in allExploits:
                            for key, value in exploit.items():
                                if value is None:
                                    exploit[key]="NA"
                        return data
                    allExploits = convert_none_for_exploits(allExploits)
                    allExploits = [{**exploit, 'dependency': 'Dependent on other exploits' if exploit['dependency'] == 'yes' else 'Self exploitable'} for exploit in allExploits]

                    allPatches = [
                        {
                            **patch,
                            'os': ', '.join([f"{os['os_name']}-{os['os_version']}" for os in json.loads(patch['os'])])
                        } for patch in patches
                    ]


                    def convert_none_for_patches(data):
                        for patch in allPatches:
                            for key, value in patch.items():
                                if value is None:
                                    patch[key]="NA"
                        return data
                    allPatches = convert_none_for_patches(allPatches)
                    
                    def format_trello_description(listOfDetection, listOfRemediation, allExploits, allPatches, workstations, servers, vulnerability_description, vul_id, mapped_priority):

                        vulnerability_section = f"### {vulnerability_description}\n\n"
                        mapped_priority_section = f"### {mapped_priority}\n\n"

                        detection_section = "## Detection Summary\n\n"
                        if listOfDetection:
                            for i, detection in enumerate(listOfDetection, 1):
                                detection_section += (
                                    f"### Detection {i} \n"
                                    f"- **CVE**: *{detection.get('CVE', 'N/A')}*\n"
                                    f"- **Severity**: *{detection.get('Severity', 'N/A')}*\n"
                                    f"- **First Identified On**: *{detection.get('first_identified_on', 'N/A')}*\n"
                                    f"- **Last Identified On**: *{detection.get('last_identified_on', 'N/A')}*\n"
                                    f"- **Patch Priority**: *{detection.get('patch_priority', 'N/A')}*\n"
                                )
                        else:
                            detection_section += "_No detections found._\n\n"

                        remediation_section = "## Remediation Steps\n\n"
                        if listOfRemediation:
                            remediation_section = (
                                f"### Remediation {i} \n"
                                f"- **Patch Solution**: *{(re.sub(r'\s+', ' ', re.sub(r'<.*?>', '', (listOfRemediation[0]).get('solution_patch', 'N/A'))).strip())}*\n"
                                f"- **Workaround**: *{(re.sub(r'\s+', ' ', re.sub(r'<.*?>', '', (listOfRemediation[0]).get('solution_workaround', 'N/A'))).strip())}*\n"
                                f"- **Preventive Measures**: *{(re.sub(r'\s+', ' ', re.sub(r'<.*?>', '', (listOfRemediation[0]).get('preventive_measure', 'N/A'))).strip())}*\n"
                                "---\n\n"
                                )
                        else:
                            remediation_section = "_No remediation steps available._\n\n"
                        exploit_section = "## Exploits\n\n"
                        if allExploits:
                            for i, exploit in enumerate(allExploits, 1):
                                exploit_section += (
                                    f"### Exploit {i} \n"
                                    f"- **Name**: *{exploit.get('name', 'N/A')}*\n"
                                    f"- **Description**: *{exploit.get('description', 'N/A')}*\n"
                                    f"- **Complexity**: *{exploit.get('complexity', 'N/A')}*\n"
                                    f"- **Dependency**: *{exploit.get('dependency', 'N/A')}*\n"
                                )
                        else:
                            exploit_section += "_No exploits found._\n\n"

                        patch_section = "## Patches\n\n"
                        if allPatches:
                            for i, patch in enumerate(allPatches, 1):
                                patch_section += (
                                    f"### Patch {i} \n"
                                    f"- **Solution**: *{patch.get('solution', 'N/A')}*\n"
                                    f"- **Description**: *{patch.get('description', 'N/A')}*\n"
                                    f"- **Complexity**: *{patch.get('complexity', 'N/A')}*\n"
                                    f"- **URL**: [Link]({patch.get('url', 'N/A')})\n"
                                    f"- **OS**: *{patch.get('os', 'N/A')}*\n"
                                    # "---\n\n"
                                )
                        else:
                            patch_section += "_No patches available._\n\n"

                        workstation_section = "## Workstations\n\n"
                        if workstations:
                            for i, workstation in enumerate(workstations, 1):
                                workstation_section += (
                                    f"### Workstation {i} \n"
                                    f"- **Host Name**: *{workstation.get('host_name', 'N/A')}*\n"
                                    f"- **IP Address**: *{workstation.get('ip_address', 'N/A')}*\n"
                                    # "---\n\n"
                                )
                        else:
                            workstation_section += "_No workstations found._\n\n"

                        server_section = "## Servers\n\n"
                        if servers:
                            for i, server in enumerate(servers, 1):
                                server_section += (
                                    f"### Server {i} \n"
                                    f"- **Host Name**: *{server.get('host_name', 'N/A')}*\n"
                                    f"- **IP Address**: *{server.get('ip_address', 'N/A')}*\n"
                                )
                        else:
                            server_section += "_No servers found._\n\n"

                        description = (
                            mapped_priority_section +
                            vulnerability_section +
                            detection_section +
                            remediation_section +
                            exploit_section +
                            patch_section +
                            workstation_section +
                            server_section
                        )

                        return description


                    description = format_trello_description(listOfDetection, listOfRemediation, allExploits, allPatches, workstations, servers,vulnerability_description, vul_id,mapped_priority)

                    query = {
                        'key': trelloKey,
                        'token': token,
                        'idList': listId,
                        "name": result.get("name") if result.get("name") else "Name not provided",
                        'desc': description
                    }

                    
                    try:
                        response = requests.post(url, params=query)
                        if response.status_code == 200:
                            checkVulIdExists = TicketingServiceDetails.objects.filter(cVulId=([key for key, value in TICKET_REFERENCE_CHOICES if value == 'Trello'][0] + "-" +str(vul_id))).exists()
                            if not checkVulIdExists:
                                ticket_data = response.json()
                                TicketingServiceDetails.objects.create(
                                        exploitsList = exploitIdList ,
                                        patchesList = patchesIdList,
                                        sq1VulId = vul_id,
                                        ticketId=None,
                                        organizationId=organization_id,
                                        ticketIdIfString = ticket_data.get("id"),
                                        cVulId = [key for key, value in TICKET_REFERENCE_CHOICES if value == 'Trello'][0] + "-" +str(vul_id),
                                        ticketServicePlatform=[key for key, value in TICKET_TYPE_CHOICES if value == 'Trello'][0],
                                        
                                    )
                            else:
                                ticketIdIfString = ticket_data.get("id")
                                url = f"https://api.trello.com/1/cards/{ticketIdIfString}"
                                query = {
                                    'key': '98fd0727355703d244288202ae96c469',
                                    'token': token,
                                    'closed': 'true'
                                }
                                response = requests.put(url, params=query)

                                if response.status_code == 200:
                                    print("Card archived successfully!")
                                else:
                                    print(f"Failed to archive card. Status code: {response.status_code}")


                    except requests.exceptions.HTTPError as http_err:
                        print(f"HTTP error occurred: {http_err}")
                    except requests.exceptions.ConnectionError as conn_err:
                        print(f"Connection error occurred: {conn_err}")
                    except requests.exceptions.Timeout as timeout_err:
                        print(f"Timeout error occurred: {timeout_err}")
                    except requests.exceptions.RequestException as req_err:
                        print(f"An error occurred: {req_err}")
                return JsonResponse({"status":"Success","message": "Cards created successfully"}, status=200)
            
            else:
                latest_existing_id = int((existing_vul_ids.last().cVulId).split('-')[1])

                if results[-1]["id"] == latest_existing_id:
                    return JsonResponse({"status":"No new vulnerabilities","message": "Nothing to add"}, status=200)
                
                elif results[-1]["id"] > latest_existing_id:
                    results = [vul for vul in results if vul["id"] > latest_existing_id]

                    for result in results:
                        vul_id = result.get("id")
                        organization_id = result.get("organization_id")

                        if vul_id not in existing_vul_ids:

                            cursor.execute("""
                            SELECT assetable_type, assetable_id
                            FROM assetables
                            WHERE vulnerabilities_id = %s
                        """, (vul_id,))
                        assetables_results = cursor.fetchall()

                        assets = {
                            "servers": [],
                            "workstations": []
                        }
                        ass_type = []
                        for i in assetables_results:
                            ass_type.append(i['assetable_type'])

                        ass_id = []
                        for i in assetables_results:
                            ass_id.append(i['assetable_id'])
                        
                        index = 0
                        for i in ass_type:
                            j = ass_id[index]
                            if i == 'App\\Models\\Workstations':
                                cursor.execute("""
                                SELECT host_name, ip_address
                                FROM workstations
                                WHERE id = %s AND organization_id = %s
                                """, (j, organization_id))
                                workstation = cursor.fetchone()
                                if workstation:
                                    assets["workstations"].append(workstation)
                                index = index+1
                            
        
                            if i == 'App\\Models\\Servers':
                                cursor.execute("""
                                SELECT host_name, ip_address
                                FROM workstations
                                WHERE id = %s AND organization_id = %s
                                """, (j, organization_id))
                                server = cursor.fetchone()
                                if server:
                                    assets["servers"].append(server)
                                index = index+1

                        mapped_priority = None

                        risk = float(result.get("risk"))

                        if 9.0 <= risk <= 10.0:
                            mapped_priority = "Risk: Critical"
                        elif 7.0 <= risk <= 8.9:
                            mapped_priority = "Risk: High"
                        elif 4.0 <= risk <= 6.9:
                            mapped_priority = "Risk: Medium"
                        elif 0.1 <= risk <= 3.9:
                            mapped_priority = "Risk: Low"

                        cursor.execute("SELECT * FROM exploits WHERE vul_id = %s AND organization_id = %s", (vul_id, organization_id))
                        exploits = cursor.fetchall()
                        exploitIdList = []
                        if exploits !=[]:
                            for exploit in exploits:
                                exploitIdList.append(exploit.get("id"))

                        cursor.execute("SELECT * FROM patch WHERE vul_id = %s", (vul_id,))
                        patches = cursor.fetchall()
                        patchesIdList = []
                        if patches !=[]:
                            for patch in patches:
                                patchesIdList.append(patch.get("id"))

                        cursor.execute("SELECT * FROM ticketing_tool WHERE organization_id = %s AND type = 'Trello'", (organization_id,))
                        ticketing_tool = cursor.fetchone()

                        if not ticketing_tool:
                            continue

                        url = (json.loads(ticketing_tool.get("values"))).get("url")+"/1/cards"
                        trelloKey = (json.loads(ticketing_tool.get("values"))).get("key")
                        token = (json.loads(ticketing_tool.get("values"))).get("token")
                        listId = (json.loads(ticketing_tool.get("values"))).get("listid")

                        resultCVEs = json.loads(result.get("CVEs", {}))
                        if isinstance(resultCVEs, dict):
                            cve_list = resultCVEs.get("cves", [])
                        else:
                            cve_list = []
                        cve_string = ", ".join(cve_list)
                        context = {
                            'result': {
                                'CVEs': cve_string,
                                'severity': result.get('severity'),
                                'first_seen': result.get('first_seen'),
                                'last_identified_on': result.get('last_identified_on'),
                                'patch_priority': result.get('patch_priority'),
                            }
                        }

                        if patches:
                            patch_data = []
                            for patch in patches:
                                patchSolution = patch.get("solution", "")
                                patchDescription = patch.get("description", "")
                                patchComplexity = patch.get("complexity", "")
                                patchType = patch.get("type", "")
                                os_list = json.loads(patch.get("os", "[]"))
                                patchOs = ", ".join(f"{os['os_name']}-{os['os_version']}" for os in os_list)

                                patch_data.append({
                                    'solution': patchSolution,
                                    'description': patchDescription,
                                    'complexity': patchComplexity,
                                    'type': patchType,
                                    'os': patchOs,
                                    'url': patch.get("url", "")
                                })

                            patchContext = {
                                'patches': patch_data
                            }
                        else:
                            patchContext = {
                                'patches': []
                            }

                        remediationObj = {
                            "solution_patch": result["solution_patch"],
                            "solution_workaround": result["solution_workaround"],
                            "preventive_measure": result["preventive_measure"],
                            }
                        cves = json.loads(result["CVEs"])
                        cves_string = ", ".join(cves["cves"])
                        detectionSummaryObj = {
                            "CVE": cves_string,
                            "Severity": result["severity"],
                            "first_identified_on": result["first_seen"],
                            "last_identifies_on":result["last_identified_on"],
                            "patch_priority":result["patch_priority"]
                            }
                        
                        vulnerability_description = None
                        if result['description'] is not None:
                            vulnerability_description = re.sub(r'\s+', ' ', re.sub(r'<.*?>', '',"Vulnerability synopsis: "+ result['description'])).strip()
                        else:
                            vulnerability_description = "Description not aded"

                        workstations = assets['workstations']

                        def convert_none_workstations(data):
                            for workstation in workstations:
                                for key, value in workstation.items():
                                    if value is None:
                                        workstation[key]="NA"
                            return data

                        workstations = convert_none_workstations(workstations)

                        servers = assets['servers']

                        def convert_none_servers(data):
                            for server in servers:
                                for key, value in server.items():
                                    if value is None:
                                        server[key]="NA"
                            return data

                        servers = convert_none_servers(servers)

                        listOfDetection = [detectionSummaryObj]

                        def convert_datetime_to_string(data):
                            for item in data:
                                for key, value in item.items():
                                    if isinstance(value, datetime):
                                        item[key] = value.strftime('%Y-%m-%d %H:%M:%S')
                            return data
                        
                        listOfDetection = convert_datetime_to_string(listOfDetection)

                        for detection in listOfDetection:
                            for key, value in detection.items():
                                if value is None:
                                    detection[key] = "NA"

                        listOfRemediation = [remediationObj]

                        def convert_none(data):
                            for remediation in listOfRemediation:
                                for key, value in remediation.items():
                                    if value is None:
                                        remediation[key]="NA"
                            return data

                        listOfRemediation = convert_none(listOfRemediation)

                        allExploits = exploits
                        def convert_none_for_exploits(data):
                            for exploit in allExploits:
                                for key, value in exploit.items():
                                    if value is None:
                                        exploit[key]="NA"
                            return data
                        allExploits = convert_none_for_exploits(allExploits)
                        allExploits = [{**exploit, 'dependency': 'Dependent on other exploits' if exploit['dependency'] == 'yes' else 'Self exploitable'} for exploit in allExploits]

                        allPatches = [
                            {
                                **patch,
                                'os': ', '.join([f"{os['os_name']}-{os['os_version']}" for os in json.loads(patch['os'])])
                            } for patch in patches
                        ]


                        def convert_none_for_patches(data):
                            for patch in allPatches:
                                for key, value in patch.items():
                                    if value is None:
                                        patch[key]="NA"
                            return data
                        allPatches = convert_none_for_patches(allPatches)

                        def format_trello_description(listOfDetection, listOfRemediation, allExploits, allPatches, workstations, servers, vulnerability_description, vul_id, mapped_priority):

                            vulnerability_section = f"### {vulnerability_description}\n\n"
                            mapped_priority_section = f"### {mapped_priority}\n\n"

                            detection_section = "## Detection Summary\n\n"
                            if listOfDetection:
                                for i, detection in enumerate(listOfDetection, 1):
                                    detection_section += (
                                        f"### Detection {i} \n"
                                        f"- **CVE**: *{detection.get('CVE', 'N/A')}*\n"
                                        f"- **Severity**: *{detection.get('Severity', 'N/A')}*\n"
                                        f"- **First Identified On**: *{detection.get('first_identified_on', 'N/A')}*\n"
                                        f"- **Last Identified On**: *{detection.get('last_identified_on', 'N/A')}*\n"
                                        f"- **Patch Priority**: *{detection.get('patch_priority', 'N/A')}*\n"
                                    )
                            else:
                                detection_section += "_No detections found._\n\n"

                            remediation_section = "## Remediation Steps\n\n"
                            if listOfRemediation:
                                remediation_section = (
                                    f"### Remediation {i} \n"
                                    f"- **Patch Solution**: *{(re.sub(r'\s+', ' ', re.sub(r'<.*?>', '', (listOfRemediation[0]).get('solution_patch', 'N/A'))).strip())}*\n"
                                    f"- **Workaround**: *{(re.sub(r'\s+', ' ', re.sub(r'<.*?>', '', (listOfRemediation[0]).get('solution_workaround', 'N/A'))).strip())}*\n"
                                    f"- **Preventive Measures**: *{(re.sub(r'\s+', ' ', re.sub(r'<.*?>', '', (listOfRemediation[0]).get('preventive_measure', 'N/A'))).strip())}*\n"
                                    )
                            else:
                                remediation_section = "_No remediation steps available._\n\n"

                            exploit_section = "## Exploits\n\n"
                            if allExploits:
                                for i, exploit in enumerate(allExploits, 1):
                                    exploit_section += (
                                        f"### Exploit {i} \n"
                                        f"- **Name**: *{exploit.get('name', 'N/A')}*\n"
                                        f"- **Description**: *{exploit.get('description', 'N/A')}*\n"
                                        f"- **Complexity**: *{exploit.get('complexity', 'N/A')}*\n"
                                        f"- **Dependency**: *{exploit.get('dependency', 'N/A')}*\n"
                                    )
                            else:
                                exploit_section += "_No exploits found._\n\n"

                            patch_section = "## Patches\n\n"
                            if allPatches:
                                for i, patch in enumerate(allPatches, 1):
                                    patch_section += (
                                        f"### Patch {i} \n"
                                        f"- **Solution**: *{patch.get('solution', 'N/A')}*\n"
                                        f"- **Description**: *{patch.get('description', 'N/A')}*\n"
                                        f"- **Complexity**: *{patch.get('complexity', 'N/A')}*\n"
                                        f"- **URL**: [Link]({patch.get('url', 'N/A')})\n"
                                        f"- **OS**: *{patch.get('os', 'N/A')}*\n"
                                    )
                            else:
                                patch_section += "_No patches available._\n\n"

                            workstation_section = "## Workstations\n\n"
                            if workstations:
                                for i, workstation in enumerate(workstations, 1):
                                    workstation_section += (
                                        f"### Workstation {i} \n"
                                        f"- **Host Name**: *{workstation.get('host_name', 'N/A')}*\n"
                                        f"- **IP Address**: *{workstation.get('ip_address', 'N/A')}*\n"
                                    )
                            else:
                                workstation_section += "_No workstations found._\n\n"

                            server_section = "## Servers\n\n"
                            if servers:
                                for i, server in enumerate(servers, 1):
                                    server_section += (
                                        f"### Server {i} \n"
                                        f"- **Host Name**: *{server.get('host_name', 'N/A')}*\n"
                                        f"- **IP Address**: *{server.get('ip_address', 'N/A')}*\n"
                                    )
                            else:
                                server_section += "_No servers found._\n\n"

                            description = (
                                mapped_priority_section +
                                vulnerability_section +
                                detection_section +
                                remediation_section +
                                exploit_section +
                                patch_section +
                                workstation_section +
                                server_section
                            )

                            return description
                        

                        description = format_trello_description(listOfDetection, listOfRemediation, allExploits, allPatches, workstations, servers,vulnerability_description, vul_id,mapped_priority)

                        combined_data = {
                            "name": result.get("name"),
                            "idList": listId,
                            "desc": description
                        }

                        query = {
                            'key': trelloKey ,
                            'token': token ,
                            'idList': listId , 
                            "name": result.get("name"),
                            'desc': description
                        }

                        
                        try:
                            response = requests.post(url, params=query)
                            if response.status_code == 200:
                                checkVulIdExists =TicketingServiceDetails.objects.filter(cVulId=([key for key, value in TICKET_REFERENCE_CHOICES if value == 'Trello'][0] + "-" +str(vul_id))).exists()
                                if not checkVulIdExists:
                                    ticket_data = response.json()
                                    TicketingServiceDetails.objects.create(
                                            exploitsList = exploitIdList ,
                                            patchesList = patchesIdList,
                                            sq1VulId = vul_id,
                                            ticketId=None,
                                            organizationId=organization_id,
                                            ticketIdIfString = ticket_data.get("id"),
                                            cVulId = [key for key, value in TICKET_REFERENCE_CHOICES if value == 'Trello'][0] + "-" +str(vul_id),
                                            ticketServicePlatform=[key for key, value in TICKET_TYPE_CHOICES if value == 'Trello'][0],
                                            
                                        )
                                else:
                                    ticketIdIfString = ticket_data.get("id")
                                    url = f"https://api.trello.com/1/cards/{ticketIdIfString}"
                                    query = {
                                        'key': '98fd0727355703d244288202ae96c469',
                                        'token': token,
                                        'closed': 'true'
                                    }
                                    response = requests.put(url, params=query)

                                    if response.status_code == 200:
                                        print("Card archived successfully!")
                                    else:
                                        print(f"Failed to archive card. Status code: {response.status_code}")
                        except requests.exceptions.HTTPError as http_err:
                            print(f"HTTP error occurred: {http_err}")
                        except requests.exceptions.ConnectionError as conn_err:
                            print(f"Connection error occurred: {conn_err}")
                        except requests.exceptions.Timeout as timeout_err:
                            print(f"Timeout error occurred: {timeout_err}")
                        except requests.exceptions.RequestException as req_err:
                            print(f"An error occurred: {req_err}")
                        else:
                            print("")
                    return JsonResponse({"status":"Success","message": "New issues added"}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

    finally:
        if connection.is_connected():
            connection.close()

def updateExploitsAndPatchesForTrello():
    connection = get_connection()
    if not connection or not connection.is_connected():
        return JsonResponse({"error": "Failed to connect to the database"}, status=500)
    
    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM ticketing_tool WHERE type = 'Trello'")
            ticketing_tools = cursor.fetchall()

            if not ticketing_tools:
                return JsonResponse({"message": "No Trello ticketing tools found"}, status=404)

            all_tickets = []

            for tool in ticketing_tools:
                try:
                    url = (json.loads(tool.get("values"))).get("url")
                    trelloKey = (json.loads(tool.get("values"))).get("key")
                    token = (json.loads(tool.get("values"))).get("token")
                    idList = (json.loads(tool.get("values"))).get("listid")

                    url = f'https://api.trello.com/1/lists/{idList}/cards'
                    params = {
                        'key': trelloKey,
                        'token': token
                    }

                    responses = requests.get(url, params=params)

                    if responses.status_code == 200:
                        data = responses.json()
                        for response in data:
                            cardId = response.get("id")
                            if TicketingServiceDetails.objects.filter(ticketIdIfString=cardId).exists():
                                ticketObj = TicketingServiceDetails.objects.get(ticketIdIfString=cardId)
                                vulnerabilityId = ticketObj.sq1VulId
                                print(vulnerabilityId)
                                organizationId = ticketObj.organizationId
                                exploitsList = ast.literal_eval(ticketObj.exploitsList)
                                patchesList = ast.literal_eval(ticketObj.patchesList)

                                cursor.execute(f"SELECT * FROM exploits WHERE vul_id = {vulnerabilityId}")
                                exploits = cursor.fetchall()

                                cursor.execute(f"SELECT * FROM patch WHERE vul_id = {vulnerabilityId}")
                                patches = cursor.fetchall()

                                cursor.execute(f"SELECT * FROM vulnerabilities WHERE id = {vulnerabilityId};")
                                vulnerabilityResult = cursor.fetchall()

                                if len(patches) > len(patchesList) or len(exploits) > len(exploitsList):
                                    vulnerability_name = vulnerabilityResult[0]['name'] if vulnerabilityResult[0]['name'] else "Description not added"
                                    vulnerability_description = vulnerabilityResult[0]['description'] if vulnerabilityResult[0]['description'] else "Description not added"

                                    vulnerability_description = None
                                    if vulnerabilityResult[0]['description'] is not None:
                                        vulnerability_description = re.sub(r'\s+', ' ', re.sub(r'<.*?>', '',"Vulnerability synopsis: "+ vulnerabilityResult[0]['description'])).strip()
                                    else:
                                        vulnerability_description = "Description not aded"
                                    
                                    cves = (vulnerabilityResult[0]).get("CVEs")
                                    cves_string = ", ".join(json.loads(cves)["cves"])
                                    detectionSummaryObj = {
                                        "CVE": cves_string,
                                        "Severity": vulnerabilityResult[0]["severity"],
                                        "first_identified_on": vulnerabilityResult[0]["first_seen"],
                                        "last_identifies_on":vulnerabilityResult[0]["last_identified_on"],
                                        "patch_priority":vulnerabilityResult[0]["patch_priority"]
                                        }
                                    listOfDetection = [detectionSummaryObj]

                                    def convert_datetime_to_string(data):
                                        for item in data:
                                            for key, value in item.items():
                                                if isinstance(value, datetime):
                                                    item[key] = value.strftime('%Y-%m-%d %H:%M:%S')
                                        return data
                                    
                                    listOfDetection = convert_datetime_to_string(listOfDetection)

                                    for detection in listOfDetection:
                                        for key, value in detection.items():
                                            if value is None:
                                                detection[key] = "NA"

                                    remediationObj = {
                                            "solution_patch": vulnerabilityResult[0]["solution_patch"],
                                            "solution_workaround": vulnerabilityResult[0]["solution_workaround"],
                                            "preventive_measure": vulnerabilityResult[0]["preventive_measure"],
                                            }
                                    listOfRemediation = [remediationObj]

                                    def convert_none(data):
                                        for remediation in listOfRemediation:
                                            for key, value in remediation.items():
                                                if value is None:
                                                    remediation[key]="NA"
                                        return data

                                    listOfRemediation = convert_none(listOfRemediation)

                                    cursor.execute("""
                                    SELECT assetable_type, assetable_id
                                    FROM assetables
                                    WHERE vulnerabilities_id = %s
                                    """, (vulnerabilityId,))
                                    assetables_results = cursor.fetchall()

                                    assets = {
                                        "servers": [],
                                        "workstations": []
                                    }
                                    ass_type = []
                                    for i in assetables_results:
                                        ass_type.append(i['assetable_type'])

                                    ass_id = []
                                    for i in assetables_results:
                                        ass_id.append(i['assetable_id'])

                                    index = 0
                                    for i in ass_type:
                                        j = ass_id[index]
                                        if i == 'App\\Models\\Workstations':
                                            cursor.execute("""
                                            SELECT host_name, ip_address
                                            FROM workstations
                                            WHERE id = %s AND organization_id = %s
                                            """, (j, organizationId))
                                            workstation = cursor.fetchone()
                                            if workstation:
                                                assets["workstations"].append(workstation)
                                            index = index+1
                                        

                                        if i == 'App\\Models\\Servers':
                                            cursor.execute("""
                                            SELECT host_name, ip_address
                                            FROM workstations
                                            WHERE id = %s AND organization_id = %s
                                            """, (j, organizationId))
                                            server = cursor.fetchone()
                                            if server:
                                                assets["servers"].append(server)
                                            index = index+1
                                    
                                    workstations = assets['workstations']

                                    def convert_none_workstations(data):
                                        for workstation in workstations:
                                            for key, value in workstation.items():
                                                if value is None:
                                                    workstation[key]="NA"
                                        return data

                                    workstations = convert_none_workstations(workstations)

                                    servers = assets['servers']

                                    def convert_none_servers(data):
                                        for server in servers:
                                            for key, value in server.items():
                                                if value is None:
                                                    server[key]="NA"
                                        return data

                                    servers = convert_none_servers(servers)

                                    allExploits = exploits
                                    def convert_none_for_exploits(data):
                                        for exploit in allExploits:
                                            for key, value in exploit.items():
                                                if value is None:
                                                    exploit[key]="NA"
                                        return data
                                    allExploits = convert_none_for_exploits(allExploits)
                                    allExploits = [{**exploit, 'dependency': 'Dependent on other exploits' if exploit['dependency'] == 'yes' else 'Self exploitable'} for exploit in allExploits]
                                    allPatches = [
                                        {
                                            **patch,
                                            'os': ', '.join([f"{os['os_name']}-{os['os_version']}" for os in json.loads(patch['os'])])
                                        } for patch in patches
                                    ]


                                    def convert_none_for_patches(data):
                                        for patch in allPatches:
                                            for key, value in patch.items():
                                                if value is None:
                                                    patch[key]="NA"
                                        return data
                                    allPatches = convert_none_for_patches(allPatches)

                                    mapped_priority = None

                                    risk = float((vulnerabilityResult[0]).get("risk"))

                                    if 9.0 <= risk <= 10.0:
                                        mapped_priority = "Risk: Critical"
                                    elif 7.0 <= risk <= 8.9:
                                        mapped_priority = "Risk: High"
                                    elif 4.0 <= risk <= 6.9:
                                        mapped_priority = "Risk: Medium"
                                    elif 0.1 <= risk <= 3.9:
                                        mapped_priority = "Risk: Low"

                                    def format_trello_description(listOfDetection, listOfRemediation, allExploits, allPatches, workstations, servers, vulnerability_description, vul_id, mapped_priority):

                                        mapped_priority_section = f"### {mapped_priority}\n\n"
                                        vulnerability_section = f"### {vulnerability_description}\n\n"

                                        detection_section = "## Detection Summary\n\n"
                                        if listOfDetection:
                                            for i, detection in enumerate(listOfDetection, 1):
                                                detection_section += (
                                                    f"### Detection {i} \n"
                                                    f"- **CVE**: *{detection.get('CVE', 'N/A')}*\n"
                                                    f"- **Severity**: *{detection.get('Severity', 'N/A')}*\n"
                                                    f"- **First Identified On**: *{detection.get('first_identified_on', 'N/A')}*\n"
                                                    f"- **Last Identified On**: *{detection.get('last_identified_on', 'N/A')}*\n"
                                                    f"- **Patch Priority**: *{detection.get('patch_priority', 'N/A')}*\n"
                                                )
                                        else:
                                            detection_section += "_No detections found._\n\n"

                                        remediation_section = "## Remediation Steps\n\n"
                                        if listOfRemediation:
                                            remediation_section = (
                                                f"### Remediation {i} \n"
                                                f"- **Patch Solution**: *{(re.sub(r'\s+', ' ', re.sub(r'<.*?>', '', (listOfRemediation[0]).get('solution_patch', 'N/A'))).strip())}*\n"
                                                f"- **Workaround**: *{(re.sub(r'\s+', ' ', re.sub(r'<.*?>', '', (listOfRemediation[0]).get('solution_workaround', 'N/A'))).strip())}*\n"
                                                f"- **Preventive Measures**: *{(re.sub(r'\s+', ' ', re.sub(r'<.*?>', '', (listOfRemediation[0]).get('preventive_measure', 'N/A'))).strip())}*\n"
                                                )
                                        else:
                                            remediation_section = "_No remediation steps available._\n\n"

                                        exploit_section = "## Exploits\n\n"
                                        if allExploits:
                                            for i, exploit in enumerate(allExploits, 1):
                                                exploit_section += (
                                                    f"### Exploit {i} \n"
                                                    f"- **Name**: *{exploit.get('name', 'N/A')}*\n"
                                                    f"- **Description**: *{exploit.get('description', 'N/A')}*\n"
                                                    f"- **Complexity**: *{exploit.get('complexity', 'N/A')}*\n"
                                                    f"- **Dependency**: *{exploit.get('dependency', 'N/A')}*\n"
                                                )
                                        else:
                                            exploit_section += "_No exploits found._\n\n"

                                        patch_section = "## Patches\n\n"
                                        if allPatches:
                                            for i, patch in enumerate(allPatches, 1):
                                                patch_section += (
                                                    f"### Patch {i} \n"
                                                    f"- **Solution**: *{patch.get('solution', 'N/A')}*\n"
                                                    f"- **Description**: *{patch.get('description', 'N/A')}*\n"
                                                    f"- **Complexity**: *{patch.get('complexity', 'N/A')}*\n"
                                                    f"- **URL**: [Link]({patch.get('url', 'N/A')})\n"
                                                    f"- **OS**: *{patch.get('os', 'N/A')}*\n"
                                                )
                                        else:
                                            patch_section += "_No patches available._\n\n"


                                        workstation_section = "## Workstations\n\n"
                                        if workstations:
                                            for i, workstation in enumerate(workstations, 1):
                                                workstation_section += (
                                                    f"### Workstation {i} \n"
                                                    f"- **Host Name**: *{workstation.get('host_name', 'N/A')}*\n"
                                                    f"- **IP Address**: *{workstation.get('ip_address', 'N/A')}*\n"
                                                )
                                        else:
                                            workstation_section += "_No workstations found._\n\n"

                                        server_section = "## Servers\n\n"
                                        if servers:
                                            for i, server in enumerate(servers, 1):
                                                server_section += (
                                                    f"### Server {i} \n"
                                                    f"- **Host Name**: *{server.get('host_name', 'N/A')}*\n"
                                                    f"- **IP Address**: *{server.get('ip_address', 'N/A')}*\n"
                                                )
                                        else:
                                            server_section += "_No servers found._\n\n"

                                        full_description = (
                                            mapped_priority_section +
                                            vulnerability_section +
                                            detection_section +
                                            remediation_section +
                                            exploit_section +
                                            patch_section +
                                            workstation_section +
                                            server_section
                                        )

                                        return full_description

                                    description = format_trello_description(
                                        listOfDetection, listOfRemediation, allExploits, 
                                        allPatches, workstations, servers, 
                                        vulnerability_description, vulnerabilityId,
                                        mapped_priority
                                    )

                                    query = {
                                        'key': trelloKey,
                                        'token': token,
                                        'idList': idList, 
                                        "name": vulnerability_name,
                                        'desc': description
                                    }

                                    putUrl = f"https://api.trello.com/1/cards/{cardId}"
                                    response = requests.put(putUrl, params=query)

                                    if response.status_code == 200:
                                        newPatchIds = [patch['id'] for patch in patches if patch['id'] not in patchesList]
                                        if newPatchIds:
                                            ticketObj.patchesList = str(patchesList + newPatchIds)
                                            ticketObj.save()

                                        newExploitIds = [exploit['id'] for exploit in exploits if exploit['id'] not in exploitsList]
                                        if newExploitIds:
                                            ticketObj.exploitsList = str(exploitsList + newExploitIds)
                                            ticketObj.save()
                                    else:
                                        return JsonResponse({"error": f"Failed to update Trello card for vulnerability {vulnerabilityId}"}, status=response.status_code)
                                else:
                                    continue

                    else:
                        return JsonResponse({"error": f"Failed to fetch Trello cards, status code: {responses.status_code}"}, status=responses.status_code)

                except Exception as e:
                    return JsonResponse({"error": f"Error processing Trello tool: {str(e)}"}, status=500)

        return JsonResponse({"message": "Trello cards updated successfully"}, status=200)

    except Exception as e:
        return JsonResponse({"error": f"Failed to process request: {str(e)}"}, status=500)

    finally:
        if connection.is_connected():
            connection.close()


def changeVulnerabilityStatusForTrello():
    connection = get_connection()
    if not connection or not connection.is_connected():
        return JsonResponse({"error": "Failed to connect to the database"}, status=500)

    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM ticketing_tool WHERE type = 'trello'")
            ticketing_tools = cursor.fetchall()

            for tool in ticketing_tools:
                api_key = (json.loads(tool.get("values"))).get("key")
                api_token = (json.loads(tool.get("values"))).get("token")
                closed_list_id = (json.loads(tool.get("values"))).get("closedListId")

                url = f"https://api.trello.com/1/lists/{closed_list_id}/cards"

                headers = {
                "Accept": "application/json"
                }

                query = {
                "key": api_key,
                "token": api_token
                }

                
                response = requests.get(url, headers=headers, params=query)
                if response.status_code == 200:
                    if len(response.json())>0:
                        cards = response.json()
                        for card in cards:
                            card_id = card.get("id")

                            if TicketingServiceDetails.objects.filter(ticketIdIfString=card_id).exists():
                                if TicketingServiceDetails.objects.get(ticketIdIfString=card_id).isActive == False:
                                    continue
                                card_details= TicketingServiceDetails.objects.get(ticketIdIfString=card_id)
                                vul_id = card_details.sq1VulId

                                card_details.isActive = False
                                card_details.save()

                                cursor.execute("SELECT * FROM vulnerabilities")

                                vulnerabilitiesInMainDB = cursor.fetchall()
                                cursor.execute(f"UPDATE vulnerabilities SET status = '1' WHERE id = {vul_id}")

                                connection.commit()
                                print()
                else:
                    print(f"Failed to get cards: {response.status_code}")

        
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        return JsonResponse({"error": str(e)}, status=500)
    
    finally:
        if connection.is_connected():
            connection.close()

    return JsonResponse({"success": "Vulnerability status updated successfully"})


def start_scheduler():
    scheduler = BackgroundScheduler(timezone=pytz.UTC)

    start_time = datetime.now(pytz.UTC).replace(hour=11, minute=50, second=0, microsecond=0)

    scheduler.add_job(freshservice_call_create_ticket, CronTrigger(hour=start_time.hour, minute=start_time.minute, day_of_week='*', start_date=start_time))
    scheduler.add_job(jira_call_create_ticket, CronTrigger(hour=start_time.hour, minute=(start_time.minute + 3) % 60, day_of_week='*', start_date=start_time))
    scheduler.add_job(createCardInTrello, CronTrigger(hour=start_time.hour, minute=(start_time.minute + 6) % 60, day_of_week='*', start_date=start_time))


    scheduler.add_job(updateExploitsAndPatchesForFreshservice, CronTrigger(hour=start_time.hour, minute=(start_time.minute + 9) % 60, day_of_week='*', start_date=start_time))
    scheduler.add_job(updateExploitsAndPatchesForJira, CronTrigger(hour=start_time.hour, minute=(start_time.minute + 12) % 60, day_of_week='*', start_date=start_time))
    scheduler.add_job(updateExploitsAndPatchesForTrello, CronTrigger(hour=start_time.hour, minute=(start_time.minute + 15) % 60, day_of_week='*', start_date=start_time))

    scheduler.add_job(changeVulnerabilityStatusForFreshService, CronTrigger(hour=start_time.hour, minute=(start_time.minute + 18) % 60, day_of_week='*', start_date=start_time))
    scheduler.add_job(changeVulnerabilityStatusForJira, CronTrigger(hour=start_time.hour, minute=(start_time.minute + 21) % 60, day_of_week='*', start_date=start_time))
    scheduler.add_job(changeVulnerabilityStatusForTrello, CronTrigger(hour=start_time.hour, minute=(start_time.minute + 24) % 60, day_of_week='*', start_date=start_time))

    scheduler.start()
