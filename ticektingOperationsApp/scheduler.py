import ast
import json
import requests
import logging
import threading
import time
import pytz

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.date import DateTrigger

from datetime import datetime, timedelta, timezone

from decouple import config

from django.http import JsonResponse

from django.template.loader import render_to_string

from requests.auth import HTTPBasicAuth

# from pytz import timezone

from .dbUtils import get_connection
from .models import *
from .ticketing_service import save_ticket_details

# Configure logging
logging.basicConfig()
logging.getLogger('apscheduler').setLevel(logging.DEBUG)

lock = threading.Lock() # globally defined

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

                        risk = float(result.get("risk"))

                        if 9.0 <= risk <= 10.0:
                            mapped_priority = 4
                        elif 7.0 <= risk <= 8.9:
                            mapped_priority = 3
                        elif 4.0 <= risk <= 6.9:
                            mapped_priority = 2
                        elif 0.1 <= risk <= 3.9:
                            mapped_priority = 1

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

                        freshservice_url = f"{ticketing_tool.get('url')}/api/v2/tickets"
                        freshservice_key = ticketing_tool.get("key")

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

                        description = result['description'] if result['description'] is not None else "Description not present"

                        combined_data = {
                            "description": description+ detection_summary_table+remediation_table+ exploits_table_html + patch_table_html+workstation_table+servers_table,
                            "subject": result.get("name"),
                            "email": "ram@freshservice.com",
                            "priority": 4,
                            "status": 2,
                            "cc_emails": ["ram@freshservice.com", "diana@freshservice.com"],
                            "workspace_id": 2,
                            "urgency": 3,
                        }

                        headers = {
                            "Content-Type": "application/json",
                            "Authorization": f"Basic {freshservice_key}"
                        }
                        response = requests.post(freshservice_url, json=combined_data, headers=headers)
                        time.sleep(3)
                        if response.status_code == 201:
                            ticket_id = response.json()['ticket'].get("id")
                            ticket_data = response.json().get("ticket", {})

                            checkVulIdExists = TicketingServiceDetails.objects.filter(sq1VulId=vul_id).exists()

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

                    return JsonResponse({"message": f"tickets created successfully."}, status=200)

                else:
                    latest_existing_id = int((existing_vul_ids.last().cVulId).split('-')[1])

                    if results[-1]["id"] == latest_existing_id:
                        return JsonResponse({"message": "Nothing to add"}, status=200)
                    
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

                            risk = float(result.get("risk"))

                            if 9.0 <= risk <= 10.0:
                                mapped_priority = 4
                            elif 7.0 <= risk <= 8.9:
                                mapped_priority = 3
                            elif 4.0 <= risk <= 6.9:
                                mapped_priority = 2
                            elif 0.1 <= risk <= 3.9:
                                mapped_priority = 1

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

                            freshservice_url = f"{ticketing_tool.get('url')}/api/v2/tickets"
                            freshservice_key = ticketing_tool.get("key")

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


                            combined_data = {
                                "description": result.get("description", "").replace("'", '"') + detection_summary_table+remediation_table+ exploits_table_html + patch_table_html+workstation_table+servers_table,
                                "subject": result.get("name"),
                                "email": "ram@freshservice.com",
                                "priority": 4,
                                "status": 2,
                                "cc_emails": ["ram@freshservice.com", "diana@freshservice.com"],
                                "workspace_id": 2,
                                "urgency": mapped_priority,
                            }

                            headers = {
                                "Content-Type": "application/json",
                                "Authorization": f"Basic {freshservice_key}"
                            }

                            response = requests.post(freshservice_url, json=combined_data, headers=headers)
                            time.sleep(3)

                            if response.status_code == 201:
                                ticket_id = response.json()['ticket'].get("id")
                                ticket_data = response.json().get("ticket", {})

                                checkVulIdExists = TicketingServiceDetails.objects.filter(sq1VulId=vul_id).exists()

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

                        return JsonResponse({"message": "tickets created successfully."}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

        finally:
            if connection.is_connected():
                connection.close()
                pass

def updateExploitsAndPatchesForFreshservice():
    connection = get_connection()
    if not connection or not connection.is_connected():
        return JsonResponse({"error": "Failed to connect to the database"}, status=500)
    
    with connection.cursor(dictionary=True) as cursor:
        cursor.execute("SELECT url, `key` FROM ticketing_tool WHERE type = 'Freshservice'")
        ticketing_tools = cursor.fetchall()

        all_tickets = []

        for tool in ticketing_tools:
            url = tool['url']
            key = tool['key']
            
            headers = {
                "Content-Type":"application/json",
                "Authorization": f"Basic {key}"
            }

            try:
                params = {
                    "per_page": 100
                }
                response = requests.get(f"{url}/api/v2/tickets", headers=headers, params = params)

                if response.status_code == 200:
                    tickets = response.json().get('tickets', [])
                    all_tickets.extend(tickets)
                else:
                    print(f"Error fetching tickets for {url}: {response.status_code} - {response.text}")
            except requests.RequestException as e:
                print(f"Request failed for {url}: {str(e)}")
        for ticket in all_tickets:
            checkTicketId = (TicketingServiceDetails.objects.filter(ticketId = ticket.get("id"))).exists()
            if checkTicketId == True:
                vulnerabilityId = (TicketingServiceDetails.objects.get(ticketId = ticket.get("id"))).sq1VulId
                organizationId = (TicketingServiceDetails.objects.get(sq1VulId = vulnerabilityId, ticketServicePlatform="freshservice")).organizationId

                ticketObj = TicketingServiceDetails.objects.get(ticketId =  ticket.get("id"))
                exploitsList = ast.literal_eval(ticketObj.exploitsList)
                patchesList = ast.literal_eval(ticketObj.patchesList)

                cursor.execute(f"SELECT * FROM exploits WHERE vul_id = {vulnerabilityId}")
                exploits = cursor.fetchall()

                cursor.execute(f"SELECT * FROM patch WHERE vul_id = {vulnerabilityId}")
                patches = cursor.fetchall()
                if len(patches) > len(patchesList) or len(exploits) > len(exploitsList):

                    cursor.execute(f"""
                    SELECT *
                    FROM vulnerabilities
                    WHERE id = {vulnerabilityId};
                    """)
                    result = cursor.fetchall()

                    mapped_priority = None

                    risk = float(result[0].get("risk"))

                    if 9.0 <= risk <= 10.0:
                        mapped_priority = 4
                    elif 7.0 <= risk <= 8.9:
                        mapped_priority = 3
                    elif 4.0 <= risk <= 6.9:
                        mapped_priority = 2
                    elif 0.1 <= risk <= 3.9:
                        mapped_priority = 1

                    cursor.execute("SELECT * FROM exploits WHERE vul_id = %s AND organization_id = %s", (vulnerabilityId, organizationId))
                    exploits = cursor.fetchall()
                    exploitIdList = []
                    if exploits !=[]:
                        for exploit in exploits:
                            exploitIdList.append(exploit.get("id"))

                    cursor.execute("SELECT * FROM patch WHERE vul_id = %s", (vulnerabilityId,))
                    patches = cursor.fetchall()
                    patchesIdList = []
                    if patches !=[]:
                        for patch in patches:
                            patchesIdList.append(patch.get("id"))

                    resultCVEs = json.loads(result[0].get("CVEs"))
                    if isinstance(resultCVEs, dict):
                        cve_list = resultCVEs.get("cves", [])
                    else:
                        cve_list = []
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

                    """
                    SELECT assetable_type, assetable_id
                    FROM assetables
                    WHERE vulnerabilities_id = %s
                    """, (vulnerabilityId,)
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
                
                    detection_summary_table = render_to_string('detection_summary_table.html', context)

                    remediationContext = {
                                "solutionPatch":result[0].get("solution_patch"),
                                "solutionWorkAround":result[0].get("solution_workaround"),
                                "preventiveMeasure":result[0].get("preventive_measure")
                            }

                    remediation_table = render_to_string('remedieationTableUpd.html', remediationContext)
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
                    vuldesc = result[0].get('description') if result[0].get('description') else "Description not added"

                    combined_data = {
                            "description": vuldesc + detection_summary_table+remediation_table+ exploits_table_html + patch_table_html+workstation_table+servers_table,
                            "subject": result[0].get('name'),
                            "email": "ram@freshservice.com",
                            "priority": 4,
                            "status": 2,
                            "cc_emails": ["ram@freshservice.com", "diana@freshservice.com"],
                            "workspace_id": 2,
                            "urgency": 3,
                        }
                    url = url+"/api/v2/tickets/"+str((ticket.get("id")))
                    headers = {
                        "Content-Type": "application/json",
                        "Authorization": f"Basic {key}"
                    }
                    response = requests.put(url, json=combined_data, headers=headers)
                    time.sleep(3)
                    if response.status_code == 200:
                        newPatchIds = [patch['id'] for patch in patches if patch['id'] not in patchesList]
                        if newPatchIds:
                            ticket_service_details = TicketingServiceDetails.objects.get(sq1VulId=vulnerabilityId,ticketServicePlatform = "freshservice")
                            existingPatchIds = ast.literal_eval(ticket_service_details.patchesList or '[]')
                            newPatchesList = existingPatchIds + newPatchIds
                            ticket_service_details.patchesList = str(newPatchesList)
                            ticket_service_details.save()
                        newExploitIds = [exploit['id'] for exploit in exploits if exploit['id'] not in exploitsList]
                        if newExploitIds:
                            ticket_service_details = TicketingServiceDetails.objects.get(sq1VulId=vulnerabilityId,ticketServicePlatform = "freshservice")
                            existingExploitIds = ast.literal_eval(ticket_service_details.exploitsList or '[]')
                            newExploitsList = existingExploitIds + newExploitIds
                            ticket_service_details.exploitsList = str(newExploitsList)
                            ticket_service_details.save()
                    else:
                        print("some error occured")
                else:
                    print("Tickets updated for the ids which had new exploits and patches")

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

                    # if 9.0 <= risk <= 10.0:
                    #     mapped_priority = 4
                    # elif 7.0 <= risk <= 8.9:
                    #     mapped_priority = 3
                    # elif 4.0 <= risk <= 6.9:
                    #     mapped_priority = 2
                    # elif 0.1 <= risk <= 3.9:
                    #     mapped_priority = 1

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

                    jira_url = f"{ticketing_tool.get('url')}"+"/rest/api/3/issue"
                    jira_key = ticketing_tool.get("key")


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
                    
                    vulnerability_description = result['description'] if result['description'] is not None else "Description not added"

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
                    
                    username = "nihar.m@secqureone.com"
                    password = ticketing_tool.get("key")

                    combined_data = {
                        "fields": {
                            "project": {
                                "key": "SCRUM"
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
                        time.sleep(3)
                        if response.status_code == 201:

                            ticket_data = response.json()
                            checkVulIdExists = TicketingServiceDetails.objects.filter(sq1VulId=vul_id).exists()
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
            
            else:
                latest_existing_id = int((existing_vul_ids.last().cVulId).split('-')[1])

                if results[-1]["id"] == latest_existing_id:
                    return JsonResponse({"message": "Nothing to add"}, status=200)
                
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

                        # if 9.0 <= risk <= 10.0:
                        #     mapped_priority = 4
                        # elif 7.0 <= risk <= 8.9:
                        #     mapped_priority = 3
                        # elif 4.0 <= risk <= 6.9:
                        #     mapped_priority = 2
                        # elif 0.1 <= risk <= 3.9:
                        #     mapped_priority = 1

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

                        jira_url = f"{ticketing_tool.get('url')}"+"/rest/api/3/issue"
                        jira_key = ticketing_tool.get("key")


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
                        
                        vulnerability_description = result['description'] if result['description'] is not None else "Description not added"

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
                        
                        username = "nihar.m@secqureone.com"
                        password = ticketing_tool.get("key")

                        combined_data = {
                            "fields": {
                                "project": {
                                    "key": "SCRUM"
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
                            time.sleep(3)
                            if response.status_code == 201:

                                ticket_data = response.json()
                                checkVulIdExists = TicketingServiceDetails.objects.filter(sq1VulId=vul_id).exists()
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

                    




    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

    finally:
        if connection.is_connected():
            connection.close()
    

def updateExploitsAndPatchesForJira():
    connection = get_connection()
    if not connection or not connection.is_connected():
        return JsonResponse({"error": "Failed to connect to the database"}, status=500)
    
    with connection.cursor(dictionary=True) as cursor:
        cursor.execute("SELECT url, `key` FROM ticketing_tool WHERE type = 'JIRA'")
        ticketing_tools = cursor.fetchall()

        all_tickets = []

        for tool in ticketing_tools:
            url = tool['url']
            key = tool['key']

            headers = {
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {key}"
                    }
            
            try:
                username = "nihar.m@secqureone.com"
                password = key
                params={
                        "maxResults": 1000
                    }
                response = requests.get((url+"/rest/api/3/search"), headers = headers,auth=HTTPBasicAuth(username, password),params=params)
                if response.status_code == 200:
                    for response in response.json()['issues']:
                        issue_key = response.get("key")
                        issueId = int(((response.get("key")).split('-')[1]))
                        checkIssueIdInTicketingService = (TicketingServiceDetails.objects.filter(ticketId = issueId)).exists()
                        if checkIssueIdInTicketingService==True:
                            vulnerabilityId = (TicketingServiceDetails.objects.get(ticketId = issueId)).sq1VulId
                            organizationId = (TicketingServiceDetails.objects.get(sq1VulId = vulnerabilityId,ticketServicePlatform = "jira")).organizationId

                            ticketObj = TicketingServiceDetails.objects.get(ticketId =issueId)
                            exploitsList = ast.literal_eval(ticketObj.exploitsList)
                            patchesList = ast.literal_eval(ticketObj.patchesList)

                            cursor.execute(f"SELECT * FROM exploits WHERE vul_id = {vulnerabilityId}")
                            exploits = cursor.fetchall()

                            cursor.execute(f"SELECT * FROM patch WHERE vul_id = {vulnerabilityId}")
                            patches = cursor.fetchall()

                            cursor.execute(f"""
                            SELECT *
                            FROM vulnerabilities
                            WHERE id = {vulnerabilityId};
                            """)
                            vulnerabilityResult = cursor.fetchall()

                            if len(patches) > len(patchesList) or len(exploits) > len(exploitsList):
                                # newPatchIds = [patch['id'] for patch in patches if patch['id'] not in patchesList]
                                # if newPatchIds:
                                #     ticket_service_details = TicketingServiceDetails.objects.get(sq1VulId=vulnerabilityId, ticketServicePlatform = 'jira')
                                #     existingPatchIds = ast.literal_eval(ticket_service_details.patchesList or '[]')
                                #     newPatchesList = existingPatchIds + newPatchIds
                                #     ticket_service_details.patchesList = str(newPatchesList)
                                #     ticket_service_details.save()
                                # newExploitIds = [exploit['id'] for exploit in exploits if exploit['id'] not in exploitsList]
                                # if newExploitIds:
                                #     ticket_service_details = TicketingServiceDetails.objects.get(sq1VulId=vulnerabilityId,ticketServicePlatform = 'jira')
                                #     existingExploitIds = ast.literal_eval(ticket_service_details.exploitsList or '[]')
                                #     newExploitsList = existingExploitIds + newExploitIds
                                #     ticket_service_details.exploitsList = str(newExploitsList)
                                #     ticket_service_details.save()

                                vulnerability_name = vulnerabilityResult[0]['name'] if vulnerabilityResult[0]['name'] is not None else "Description not added"

                                vulnerability_description = vulnerabilityResult[0]['description'] if vulnerabilityResult[0]['description'] is not None else "Description not added"

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
                                                "key": "SCRUM"
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
                                    "Authorization": f"Bearer {key}"
                                }

                                response = requests.put(f"{url}/rest/api/3/issue/{issue_key}",data=json.dumps(combined_data), headers = headers,auth=HTTPBasicAuth(username, password))
                                time.sleep(3)
                                if response.status_code == 204:
                                    newPatchIds = [patch['id'] for patch in patches if patch['id'] not in patchesList]
                                    if newPatchIds:
                                        ticket_service_details = TicketingServiceDetails.objects.get(sq1VulId=vulnerabilityId, ticketServicePlatform = 'jira')
                                        existingPatchIds = ast.literal_eval(ticket_service_details.patchesList or '[]')
                                        newPatchesList = existingPatchIds + newPatchIds
                                        ticket_service_details.patchesList = str(newPatchesList)
                                        ticket_service_details.save()
                                    newExploitIds = [exploit['id'] for exploit in exploits if exploit['id'] not in exploitsList]
                                    if newExploitIds:
                                        ticket_service_details = TicketingServiceDetails.objects.get(sq1VulId=vulnerabilityId,ticketServicePlatform = 'jira')
                                        existingExploitIds = ast.literal_eval(ticket_service_details.exploitsList or '[]')
                                        newExploitsList = existingExploitIds + newExploitIds
                                        ticket_service_details.exploitsList = str(newExploitsList)
                                        ticket_service_details.save()
                                
                                else:
                                    print("Failed to update ticket for vulnerability")

            except Exception as e:
                return JsonResponse({})
            
def changeVulnerabilityStatusForFreshService():
    connection = get_connection()
    if not connection or not connection.is_connected():
        return JsonResponse({"error": "Failed to connect to the database"}, status=500)
    
    with connection.cursor(dictionary=True) as cursor:
        cursor.execute("SELECT url, `key` FROM ticketing_tool WHERE type = 'Freshservice'")
        ticketing_tools = cursor.fetchall()

        all_tickets = []

        for tool in ticketing_tools:
            url = tool['url']
            key = tool['key']
            
            headers = {
                "Content-Type":"application/json",
                "Authorization": f"Basic {key}"
            }

            try:
                params = {
                    "per_page": 100
                }
                response = requests.get(f"{url}/api/v2/tickets", headers=headers, params = params)

                if response.status_code == 200:
                    tickets = response.json().get('tickets', [])
                    all_tickets.extend(tickets)
                    for ticket in all_tickets:
                        if ticket.get("status") ==4:
                            vulId = (TicketingServiceDetails.objects.get(createdTicketId = ticket.get("id"))).sq1VulId
                            cursor.execute(f"update vulnerabilities set status = 1 where id = {vulId};")
                else:
                    print(f"Error fetching tickets for {url}: {response.status_code} - {response.text}")
            except requests.RequestException as e:
                print(f"Request failed for {url}: {str(e)}")
            
# def changeVulnerabilityStatusForJira():
#     connection = get_connection()
#     if not connection or not connection.is_connected():
#         return JsonResponse({"error": "Failed to connect to the database"}, status=500)
    
#     with connection.cursor(dictionary=True) as cursor:
#         cursor.execute("SELECT url, `key` FROM ticketing_tool WHERE type = 'JIRA'")
#         ticketing_tools = cursor.fetchall()

#         all_tickets = []

#         for tool in ticketing_tools:
#             url = tool['url']
#             key = tool['key']

#             headers = {
#                         "Content-Type": "application/json",
#                         "Authorization": f"Bearer {key}"
#                     }
            
#             try:
#                 username = "nihar.m@secqureone.com"
#                 password = key
#                 params={
#                         "maxResults": 1000
#                     }
#                 response = requests.get((url+"/rest/api/3/search"), headers = headers,auth=HTTPBasicAuth(username, password),params=params)
#                 if response.status_code == 200:
#                     for response in response.json()['issues']:
#                         if response['fields']['status']['name'] == "Completed":
#                             issueId = int(((response.get("key")).split('-')[1]))
#                             vulId = (TicketingServiceDetails.objects.get(createdTicketId = issueId)).sq1VulId
#                             cursor.execute(f"update vulnerabilities set status = 1 where id = {vulId};")
#             except Exception as e:
#                 print(e)

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

                    # if 9.0 <= risk <= 10.0:
                    #     mapped_priority = 4
                    # elif 7.0 <= risk <= 8.9:
                    #     mapped_priority = 3
                    # elif 4.0 <= risk <= 6.9:
                    #     mapped_priority = 2
                    # elif 0.1 <= risk <= 3.9:
                    #     mapped_priority = 1

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

                    url = ticketing_tool.get("url")+"/1/cards"
                    key = ticketing_tool.get("key")
                    token = ticketing_tool.get("token")
                    listId = ticketing_tool.get("listId")

                    

                    


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
                    
                    vulnerability_description = result['description'] if result['description'] is not None else "Description not added"

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
                    
                    def format_trello_description(listOfDetection, listOfRemediation, allExploits, allPatches, workstations, servers, vulnerability_description, vul_id):

                        # Adding the vulnerability description at the top with a prominent title
                        vulnerability_section = f"# **{vulnerability_description}**\n\n"

                        # Detection section with subheadings for each detection
                        detection_section = "## Detection Summary\n\n"
                        if listOfDetection:
                            for i, detection in enumerate(listOfDetection, 1):
                                detection_section += f"### Detection {i} \n\n"
                                detection_section += f"- **CVE**: *{detection.get('CVE', 'N/A')}*\n"
                                detection_section += f"- **Severity**: *{detection.get('Severity', 'N/A')}*\n"
                                detection_section += f"- **First Identified On**: *{detection.get('first_identified_on', 'N/A')}*\n"
                                detection_section += f"- **Last Identified On**: *{detection.get('last_identifies_on', 'N/A')}*\n"
                                detection_section += f"- **Patch Priority**: *{detection.get('patch_priority', 'N/A')}*\n\n"
                                detection_section += "---\n\n"  # Add a horizontal rule to separate detections
                        else:
                            detection_section += "_No detections found._\n\n"

                        # Remediation section with subheadings for each remediation
                        remediation_section = "## Remediation Steps\n\n"
                        if listOfRemediation:
                            for i, remediation in enumerate(listOfRemediation, 1):
                                remediation_section += f"### Remediation {i} \n\n"
                                remediation_section += f"- **Patch Solution**: *{remediation.get('solution_patch', 'N/A')}*\n"
                                remediation_section += f"- **Workaround**: *{remediation.get('solution_workaround', 'N/A')}*\n"
                                remediation_section += f"- **Preventive Measures**: *{remediation.get('preventive_measure', 'N/A')}*\n\n"
                                remediation_section += "---\n\n"  # Horizontal rule between items
                        else:
                            remediation_section += "_No remediation steps available._\n\n"

                        # Exploits section with clear divisions for each exploit
                        exploit_section = "## Exploits\n\n"
                        if allExploits:
                            for i, exploit in enumerate(allExploits, 1):
                                exploit_section += f"### Exploit {i} \n\n"
                                exploit_section += f"- **Name**: *{exploit.get('name', 'N/A')}*\n"
                                exploit_section += f"- **Description**: *{exploit.get('description', 'N/A')}*\n"
                                exploit_section += f"- **Complexity**: *{exploit.get('complexity', 'N/A')}*\n"
                                exploit_section += f"- **Dependency**: *{exploit.get('dependency', 'N/A')}*\n\n"
                                exploit_section += "---\n\n"  # Horizontal rule between exploits
                        else:
                            exploit_section += "_No exploits found._\n\n"

                        # Patches section with clear divisions for each patch
                        patch_section = "## Patches\n\n"
                        if allPatches:
                            for i, patch in enumerate(allPatches, 1):
                                patch_section += f"### Patch {i} \n\n"
                                patch_section += f"- **Solution**: *{patch.get('solution', 'N/A')}*\n"
                                patch_section += f"- **Description**: *{patch.get('description', 'N/A')}*\n"
                                patch_section += f"- **Complexity**: *{patch.get('complexity', 'N/A')}*\n"
                                patch_section += f"- **URL**: [Link]({patch.get('url', 'N/A')})\n"  # URL link formatting
                                patch_section += f"- **OS**: *{patch.get('os', 'N/A')}*\n\n"
                                patch_section += "---\n\n"  # Horizontal rule between patches
                        else:
                            patch_section += "_No patches available._\n\n"

                        # Workstation section with detailed lists
                        workstation_section = "## Workstations\n\n"
                        if workstations:
                            for i, workstation in enumerate(workstations, 1):
                                workstation_section += f"### Workstation {i} \n\n"
                                workstation_section += f"- **Host Name**: *{workstation.get('host_name', 'N/A')}*\n"
                                workstation_section += f"- **IP Address**: *{workstation.get('ip_address', 'N/A')}*\n\n"
                                workstation_section += "---\n\n"
                        else:
                            workstation_section += "_No workstations found._\n\n"

                        # Server section with detailed lists
                        server_section = "## Servers\n\n"
                        if servers:
                            for i, server in enumerate(servers, 1):
                                server_section += f"### Server {i} \n\n"
                                server_section += f"- **Host Name**: *{server.get('host_name', 'N/A')}*\n"
                                server_section += f"- **IP Address**: *{server.get('ip_address', 'N/A')}*\n\n"
                                server_section += "---\n\n"
                        else:
                            server_section += "_No servers found._\n\n"

                        # Combine all sections
                        description = (
                            vulnerability_section +
                            detection_section +
                            remediation_section +
                            exploit_section +
                            patch_section +
                            workstation_section +
                            server_section
                        )

                        return description


                    description = format_trello_description(listOfDetection, listOfRemediation, allExploits, allPatches, workstations, servers,vulnerability_description, vul_id)

                    query = {
                        'key': '98fd0727355703d244288202ae96c469',
                        'token': 'ATTAa35ff7e9f72c9384db1c8cede7cbe24ffb5daaa0c5a3fac34530e2c12e4ed5d57DAC2770',
                        'idList': '66dec5e96055fd0afe3273ec',  # The ID of the list where the card will be created
                        "name": result.get("name"),
                        'desc': description
                    }

                    
                    try:
                        response = requests.post(url, params=query)
                        if response.status_code == 201:
                            checkVulIdExists = TicketingServiceDetails.objects.filter(sq1VulId=vul_id).exists()
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
                latest_existing_id = int((existing_vul_ids.last().cVulId).split('-')[1])

                if results[-1]["id"] == latest_existing_id:
                    return JsonResponse({"message": "Nothing to add"}, status=200)
                
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

                        # if 9.0 <= risk <= 10.0:
                        #     mapped_priority = 4
                        # elif 7.0 <= risk <= 8.9:
                        #     mapped_priority = 3
                        # elif 4.0 <= risk <= 6.9:
                        #     mapped_priority = 2
                        # elif 0.1 <= risk <= 3.9:
                        #     mapped_priority = 1

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

                        url = ticketing_tool.get("url")+"/1/cards"
                        key = ticketing_tool.get("key")
                        token = ticketing_tool.get("token")
                        listId = ticketing_tool.get("listId")

                        

                        


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
                        
                        vulnerability_description = result['description'] if result['description'] is not None else "Description not added"

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
                        
                        def format_trello_description(listOfDetection, listOfRemediation, allExploits, allPatches, workstations, servers, vulnerability_description, vul_id):

                            # Adding the vulnerability description at the top with a prominent title
                            vulnerability_section = f"# **{vulnerability_description}**\n\n"

                            # Detection section with subheadings for each detection
                            detection_section = "## Detection Summary\n\n"
                            if listOfDetection:
                                for i, detection in enumerate(listOfDetection, 1):
                                    detection_section += f"### Detection {i} \n\n"
                                    detection_section += f"- **CVE**: *{detection.get('CVE', 'N/A')}*\n"
                                    detection_section += f"- **Severity**: *{detection.get('Severity', 'N/A')}*\n"
                                    detection_section += f"- **First Identified On**: *{detection.get('first_identified_on', 'N/A')}*\n"
                                    detection_section += f"- **Last Identified On**: *{detection.get('last_identifies_on', 'N/A')}*\n"
                                    detection_section += f"- **Patch Priority**: *{detection.get('patch_priority', 'N/A')}*\n\n"
                                    detection_section += "---\n\n"  # Add a horizontal rule to separate detections
                            else:
                                detection_section += "_No detections found._\n\n"

                            # Remediation section with subheadings for each remediation
                            remediation_section = "## Remediation Steps\n\n"
                            if listOfRemediation:
                                for i, remediation in enumerate(listOfRemediation, 1):
                                    remediation_section += f"### Remediation {i} \n\n"
                                    remediation_section += f"- **Patch Solution**: *{remediation.get('solution_patch', 'N/A')}*\n"
                                    remediation_section += f"- **Workaround**: *{remediation.get('solution_workaround', 'N/A')}*\n"
                                    remediation_section += f"- **Preventive Measures**: *{remediation.get('preventive_measure', 'N/A')}*\n\n"
                                    remediation_section += "---\n\n"  # Horizontal rule between items
                            else:
                                remediation_section += "_No remediation steps available._\n\n"

                            # Exploits section with clear divisions for each exploit
                            exploit_section = "## Exploits\n\n"
                            if allExploits:
                                for i, exploit in enumerate(allExploits, 1):
                                    exploit_section += f"### Exploit {i} \n\n"
                                    exploit_section += f"- **Name**: *{exploit.get('name', 'N/A')}*\n"
                                    exploit_section += f"- **Description**: *{exploit.get('description', 'N/A')}*\n"
                                    exploit_section += f"- **Complexity**: *{exploit.get('complexity', 'N/A')}*\n"
                                    exploit_section += f"- **Dependency**: *{exploit.get('dependency', 'N/A')}*\n\n"
                                    exploit_section += "---\n\n"  # Horizontal rule between exploits
                            else:
                                exploit_section += "_No exploits found._\n\n"

                            # Patches section with clear divisions for each patch
                            patch_section = "## Patches\n\n"
                            if allPatches:
                                for i, patch in enumerate(allPatches, 1):
                                    patch_section += f"### Patch {i} \n\n"
                                    patch_section += f"- **Solution**: *{patch.get('solution', 'N/A')}*\n"
                                    patch_section += f"- **Description**: *{patch.get('description', 'N/A')}*\n"
                                    patch_section += f"- **Complexity**: *{patch.get('complexity', 'N/A')}*\n"
                                    patch_section += f"- **URL**: [Link]({patch.get('url', 'N/A')})\n"  # URL link formatting
                                    patch_section += f"- **OS**: *{patch.get('os', 'N/A')}*\n\n"
                                    patch_section += "---\n\n"  # Horizontal rule between patches
                            else:
                                patch_section += "_No patches available._\n\n"

                            # Workstation section with detailed lists
                            workstation_section = "## Workstations\n\n"
                            if workstations:
                                for i, workstation in enumerate(workstations, 1):
                                    workstation_section += f"### Workstation {i} \n\n"
                                    workstation_section += f"- **Host Name**: *{workstation.get('host_name', 'N/A')}*\n"
                                    workstation_section += f"- **IP Address**: *{workstation.get('ip_address', 'N/A')}*\n\n"
                                    workstation_section += "---\n\n"
                            else:
                                workstation_section += "_No workstations found._\n\n"

                            # Server section with detailed lists
                            server_section = "## Servers\n\n"
                            if servers:
                                for i, server in enumerate(servers, 1):
                                    server_section += f"### Server {i} \n\n"
                                    server_section += f"- **Host Name**: *{server.get('host_name', 'N/A')}*\n"
                                    server_section += f"- **IP Address**: *{server.get('ip_address', 'N/A')}*\n\n"
                                    server_section += "---\n\n"
                            else:
                                server_section += "_No servers found._\n\n"

                            # Combine all sections
                            description = (
                                vulnerability_section +
                                detection_section +
                                remediation_section +
                                exploit_section +
                                patch_section +
                                workstation_section +
                                server_section
                            )

                            return description

                        description = format_trello_description(listOfDetection, listOfRemediation, allExploits, allPatches, workstations, servers,vulnerability_description, vul_id)

                        combined_data = {
                            "name": result.get("name"),
                            "idList": listId,
                            "desc": description
                        }

                        query = {
                            'key': '98fd0727355703d244288202ae96c469',
                            'token': 'ATTAa35ff7e9f72c9384db1c8cede7cbe24ffb5daaa0c5a3fac34530e2c12e4ed5d57DAC2770',
                            'idList': '66dec5e96055fd0afe3273ec', 
                            "name": result.get("name"),
                            'desc': description
                        }

                        
                        try:
                            response = requests.post(url, params=query)
                            if response.status_code == 201:
                                checkVulIdExists = TicketingServiceDetails.objects.filter(sq1VulId=vul_id).exists()
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

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

    finally:
        if connection.is_connected():
            connection.close()

def updateExploitsAndPatchesForTrello():
    connection = get_connection()
    if not connection or not connection.is_connected():
        return JsonResponse({"error": "Failed to connect to the database"}, status=500)
    
    with connection.cursor(dictionary=True) as cursor:
        cursor.execute("SELECT url, `key` FROM ticketing_tool WHERE type = 'Trello'")
        ticketing_tools = cursor.fetchall()

        all_tickets = []

        for tool in ticketing_tools:
            url = tool['url']
            key = tool['key']
            token = "ATTAa35ff7e9f72c9384db1c8cede7cbe24ffb5daaa0c5a3fac34530e2c12e4ed5d57DAC2770"
            idList = "66dec5e96055fd0afe3273ec"

            try:
                url = f'https://api.trello.com/1/lists/{idList}/cards'
                params = {
                    'key': key,
                    'token': token
                }

                responses = requests.get(url, params=params)
                if responses.status_code == 200:
                    data = responses.json()
                    for response in data:
                        cardId = response.get("id")
                        checkCarIdInTicketingService = (TicketingServiceDetails.objects.filter(ticketIdIfString = cardId)).exists()
                        if checkCarIdInTicketingService==True:
                            vulnerabilityId = (TicketingServiceDetails.objects.get(ticketIdIfString = cardId)).sq1VulId
                            # organizationId = (Vulnerabilities.objects.get(vulId = vulnerabilityId,ticketServicePlatform = "trello")).organizationId
                            organizationId = (TicketingServiceDetails.objects.get(sq1VulId = vulnerabilityId,ticketServicePlatform = "trello")).organizationId

                            ticketObj = TicketingServiceDetails.objects.get(ticketIdIfString =cardId)
                            exploitsList = ast.literal_eval(ticketObj.exploitsList)
                            patchesList = ast.literal_eval(ticketObj.patchesList)

                            cursor.execute(f"SELECT * FROM exploits WHERE vul_id = {vulnerabilityId}")
                            exploits = cursor.fetchall()

                            cursor.execute(f"SELECT * FROM patch WHERE vul_id = {vulnerabilityId}")
                            patches = cursor.fetchall()

                            cursor.execute(f"""
                            SELECT *
                            FROM vulnerabilities
                            WHERE id = {vulnerabilityId};
                            """)
                            vulnerabilityResult = cursor.fetchall()

                            if len(patches) > len(patchesList) or len(exploits) > len(exploitsList):

                                vulnerability_name = vulnerabilityResult[0]['name'] if vulnerabilityResult[0]['name'] is not None else "Description not added"

                                vulnerability_description = vulnerabilityResult[0]['description'] if vulnerabilityResult[0]['description'] is not None else "Description not added"

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

                                def format_trello_description(listOfDetection, listOfRemediation, allExploits, allPatches, workstations, servers, vulnerability_description, vul_id):

                                    # Adding the vulnerability description at the top with a prominent title
                                    vulnerability_section = f"# **{vulnerability_description}**\n\n"

                                    # Detection section with subheadings for each detection
                                    detection_section = "## Detection Summary\n\n"
                                    if listOfDetection:
                                        for i, detection in enumerate(listOfDetection, 1):
                                            detection_section += f"### Detection {i} \n\n"
                                            detection_section += f"- **CVE**: *{detection.get('CVE', 'N/A')}*\n"
                                            detection_section += f"- **Severity**: *{detection.get('Severity', 'N/A')}*\n"
                                            detection_section += f"- **First Identified On**: *{detection.get('first_identified_on', 'N/A')}*\n"
                                            detection_section += f"- **Last Identified On**: *{detection.get('last_identifies_on', 'N/A')}*\n"
                                            detection_section += f"- **Patch Priority**: *{detection.get('patch_priority', 'N/A')}*\n\n"
                                            detection_section += "---\n\n"  # Add a horizontal rule to separate detections
                                    else:
                                        detection_section += "_No detections found._\n\n"

                                    # Remediation section with subheadings for each remediation
                                    remediation_section = "## Remediation Steps\n\n"
                                    if listOfRemediation:
                                        for i, remediation in enumerate(listOfRemediation, 1):
                                            remediation_section += f"### Remediation {i} \n\n"
                                            remediation_section += f"- **Patch Solution**: *{remediation.get('solution_patch', 'N/A')}*\n"
                                            remediation_section += f"- **Workaround**: *{remediation.get('solution_workaround', 'N/A')}*\n"
                                            remediation_section += f"- **Preventive Measures**: *{remediation.get('preventive_measure', 'N/A')}*\n\n"
                                            remediation_section += "---\n\n"  # Horizontal rule between items
                                    else:
                                        remediation_section += "_No remediation steps available._\n\n"

                                    # Exploits section with clear divisions for each exploit
                                    exploit_section = "## Exploits\n\n"
                                    if allExploits:
                                        for i, exploit in enumerate(allExploits, 1):
                                            exploit_section += f"### Exploit {i} \n\n"
                                            exploit_section += f"- **Name**: *{exploit.get('name', 'N/A')}*\n"
                                            exploit_section += f"- **Description**: *{exploit.get('description', 'N/A')}*\n"
                                            exploit_section += f"- **Complexity**: *{exploit.get('complexity', 'N/A')}*\n"
                                            exploit_section += f"- **Dependency**: *{exploit.get('dependency', 'N/A')}*\n\n"
                                            exploit_section += "---\n\n"  # Horizontal rule between exploits
                                    else:
                                        exploit_section += "_No exploits found._\n\n"

                                    # Patches section with clear divisions for each patch
                                    patch_section = "## Patches\n\n"
                                    if allPatches:
                                        for i, patch in enumerate(allPatches, 1):
                                            patch_section += f"### Patch {i} \n\n"
                                            patch_section += f"- **Solution**: *{patch.get('solution', 'N/A')}*\n"
                                            patch_section += f"- **Description**: *{patch.get('description', 'N/A')}*\n"
                                            patch_section += f"- **Complexity**: *{patch.get('complexity', 'N/A')}*\n"
                                            patch_section += f"- **URL**: [Link]({patch.get('url', 'N/A')})\n"  # URL link formatting
                                            patch_section += f"- **OS**: *{patch.get('os', 'N/A')}*\n\n"
                                            patch_section += "---\n\n"  # Horizontal rule between patches
                                    else:
                                        patch_section += "_No patches available._\n\n"

                                    # Workstation section with detailed lists
                                    workstation_section = "## Workstations\n\n"
                                    if workstations:
                                        for i, workstation in enumerate(workstations, 1):
                                            workstation_section += f"### Workstation {i} \n\n"
                                            workstation_section += f"- **Host Name**: *{workstation.get('host_name', 'N/A')}*\n"
                                            workstation_section += f"- **IP Address**: *{workstation.get('ip_address', 'N/A')}*\n\n"
                                            workstation_section += "---\n\n"
                                    else:
                                        workstation_section += "_No workstations found._\n\n"

                                    # Server section with detailed lists
                                    server_section = "## Servers\n\n"
                                    if servers:
                                        for i, server in enumerate(servers, 1):
                                            server_section += f"### Server {i} \n\n"
                                            server_section += f"- **Host Name**: *{server.get('host_name', 'N/A')}*\n"
                                            server_section += f"- **IP Address**: *{server.get('ip_address', 'N/A')}*\n\n"
                                            server_section += "---\n\n"
                                    else:
                                        server_section += "_No servers found._\n\n"

                                    # Combine all sections
                                    description = (
                                        vulnerability_section +
                                        detection_section +
                                        remediation_section +
                                        exploit_section +
                                        patch_section +
                                        workstation_section +
                                        server_section
                                    )

                                    return description

                                description = format_trello_description(listOfDetection, listOfRemediation, allExploits, allPatches, workstations, servers,vulnerability_description, vulnerabilityId)

                                combined_data = {
                                    "name": vulnerabilityResult[0]['name'],
                                    "idList": idList,
                                    "desc": description
                                }

                                query = {
                                    'key': '98fd0727355703d244288202ae96c469',
                                    'token': 'ATTAa35ff7e9f72c9384db1c8cede7cbe24ffb5daaa0c5a3fac34530e2c12e4ed5d57DAC2770',
                                    'idList': '66dec5e96055fd0afe3273ec', 
                                    "name": vulnerabilityResult[0]['name'],
                                    'desc': description
                                }
                                putUrl = f"https://api.trello.com/1/cards/{cardId}"
                                
                                try:
                                    response = requests.put(putUrl, params=query)
                                    if response.status_code==200:
                                        newPatchIds = [patch['id'] for patch in patches if patch['id'] not in patchesList]
                                        if newPatchIds:
                                            ticket_service_details = TicketingServiceDetails.objects.get(sq1VulId=vulnerabilityId, ticketServicePlatform = 'trello')
                                            existingPatchIds = ast.literal_eval(ticket_service_details.patchesList or '[]')
                                            newPatchesList = existingPatchIds + newPatchIds
                                            ticket_service_details.patchesList = str(newPatchesList)
                                            ticket_service_details.save()
                                        newExploitIds = [exploit['id'] for exploit in exploits if exploit['id'] not in exploitsList]
                                        if newExploitIds:
                                            ticket_service_details = TicketingServiceDetails.objects.get(sq1VulId=vulnerabilityId,ticketServicePlatform = 'trello')
                                            existingExploitIds = ast.literal_eval(ticket_service_details.exploitsList or '[]')
                                            newExploitsList = existingExploitIds + newExploitIds
                                            ticket_service_details.exploitsList = str(newExploitsList)
                                            ticket_service_details.save()

                                except Exception as e:
                                    print(e)


            except Exception as e:
                print(e)




def start_scheduler():
    scheduler = BackgroundScheduler()

    scheduler.add_job(freshservice_call_create_ticket, CronTrigger(hour=3, minute=20))

    scheduler.add_job(jira_call_create_ticket, CronTrigger(hour=3, minute=25))

    scheduler.add_job(createCardInTrello, CronTrigger(hour=3, minute=30))

    scheduler.add_job(updateExploitsAndPatchesForFreshservice, CronTrigger(hour=3, minute=35))

    scheduler.add_job(updateExploitsAndPatchesForJira, CronTrigger(hour=3, minute=40))

    scheduler.add_job(updateExploitsAndPatchesForTrello,  CronTrigger(hour=3, minute=45))

    scheduler.start()