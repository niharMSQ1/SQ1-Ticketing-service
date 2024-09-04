import ast
import json
import requests

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from datetime import datetime

from decouple import config

from django.http import JsonResponse

from django.template.loader import render_to_string

from requests.auth import HTTPBasicAuth

from .dbUtils import get_connection
from .models import *
from .ticketing_service import save_ticket_details, save_vulnerability


def freshservice_call_create_ticket():
    connection = get_connection()
    if not connection or not connection.is_connected():
        return JsonResponse({"error": "Failed to connect to the database"}, status=500)

    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM vulnerabilities ORDER BY id DESC")
            results = cursor.fetchall()

            existing_vul_ids = Vulnerabilities.objects.filter(ticketServicePlatform="Freshservice")

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

                    combined_data = {
                        "description": result.get("description", "").replace("'", '"') + detection_summary_table+remediation_table+ exploits_table_html + patch_table_html+workstation_table+servers_table,
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
                    print(vul_id)
                    response = requests.post(freshservice_url, json=combined_data, headers=headers)
                    if response.status_code == 201:
                        ticket_id = response.json()['ticket'].get("id")
                        ticket_data = response.json().get("ticket", {})
                        save_vulnerability(vul_id=vul_id, organization_id=organization_id, ticket_id=ticket_id)
                        save_ticket_details(ticket_data, vul_id, exploitIdList,patchesIdList)
                    else:
                        print(f"Failed to create ticket for vulnerability {freshservice_url} {vul_id}: {response.json()}")

                return JsonResponse({"message": f"tickets created successfully."}, status=200)

            else:
                latest_existing_id = max(existing_vul_ids)

                if results[0]["id"] == latest_existing_id:
                    return JsonResponse({"message": "Nothing to add"}, status=200)
                
                elif results[0]["id"] > latest_existing_id:
                    new_vulnerabilities = [vul for vul in results if vul["id"] > latest_existing_id]

                    for result in new_vulnerabilities:
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

                        if response.status_code == 201:
                            ticket_id = response.json()['ticket'].get("id")
                            ticket_data = response.json().get("ticket", {})
                            save_vulnerability(vul_id=vul_id, organization_id=organization_id, ticket_id=ticket_id)
                            save_ticket_details(ticket_data, vul_id, exploitIdList,patchesIdList)
                            print(f"Ticket created successfully for vulnerabilities")
                        else:
                            print(f"Failed to create ticket for vulnerability {vul_id}: {response.json()}")

                    return JsonResponse({"message": "tickets created successfully."}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

    finally:
        if connection.is_connected():
            connection.close()

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
                response = requests.get(f"{url}/api/v2/tickets", headers=headers)

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
                organizationId = (Vulnerabilities.objects.get(vulId = vulnerabilityId)).organizationId

                ticketObj = TicketingServiceDetails.objects.get(ticketId =  ticket.get("id"))
                exploitsList = ast.literal_eval(ticketObj.exploitsList)
                patchesList = ast.literal_eval(ticketObj.patchesList)

                cursor.execute(f"SELECT * FROM exploits WHERE vul_id = {vulnerabilityId}")
                exploits = cursor.fetchall()

                cursor.execute(f"SELECT * FROM patch WHERE vul_id = {vulnerabilityId}")
                patches = cursor.fetchall()
                print()
                if len(patches) > len(patchesList) or len(exploits) > len(exploitsList):
                    newPatchIds = [patch['id'] for patch in patches if patch['id'] not in patchesList]
                    if newPatchIds:
                        ticket_service_details = TicketingServiceDetails.objects.get(sq1VulId=vulnerabilityId)
                        existingPatchIds = ast.literal_eval(ticket_service_details.patchesList or '[]')
                        newPatchesList = existingPatchIds + newPatchIds
                        ticket_service_details.patchesList = str(newPatchesList)
                        ticket_service_details.save()
                    newExploitIds = [exploit['id'] for exploit in exploits if exploit['id'] not in exploitsList]
                    if newExploitIds:
                        ticket_service_details = TicketingServiceDetails.objects.get(sq1VulId=vulnerabilityId)
                        existingExploitIds = ast.literal_eval(ticket_service_details.exploitsList or '[]')
                        newExploitsList = existingExploitIds + newExploitIds
                        ticket_service_details.exploitsList = str(newExploitsList)
                        ticket_service_details.save()

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

                    combined_data = {
                            "description": result[0].get('description').replace("'", '"') + detection_summary_table+remediation_table+ exploits_table_html + patch_table_html+workstation_table+servers_table,
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
                    if response.status_code == 201:
                        ticket_id = response.json()['ticket'].get("id")
                        ticket_data = response.json().get("ticket", {})
                        # save_vulnerability(vul_id=vul_id, organization_id=organization_id, ticket_id=ticket_id)
                        # save_ticket_details(ticket_data, vul_id, exploitIdList,patchesIdList)
                    else:
                        print(f"Failed to create ticket for vulnerability {url} {vulnerabilityId}: {response.json()}")

def jira_call_create_ticket():
    connection = get_connection()
    if not connection or not connection.is_connected():
        return JsonResponse({"error": "Failed to connect to the database"}, status=500)

    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM vulnerabilities ORDER BY id DESC")
            results = cursor.fetchall()

            existing_vul_ids = Vulnerabilities.objects.filter(ticketServicePlatform="Jira")

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
                    
                    vulnerability_description = result['description']
                    workstations = assets['workstations']
                    servers = assets['servers']

                    listOfDetection = [detectionSummaryObj]

                    def convert_datetime_to_string(data):
                        for item in data:
                            for key, value in item.items():
                                if isinstance(value, datetime):
                                    item[key] = value.strftime('%Y-%m-%d %H:%M:%S')
                        return data
                    
                    listOfDetection = convert_datetime_to_string(listOfDetection)

                    listOfRemediation = [remediationObj]
                    allExploits = exploits
                    allPatches = patches            

                    username = "nihar.m@secqureone.com"
                    password = ticketing_tool.get("key")


                    combined_data = {
                        "fields": {
                            "project": {
                                "key": "SCRUM"
                            },
                            "summary": "Dynamic Issue Summary",
                            "description": {
                                "version": 1,
                                "type": "doc",
                                "content": [
                                    {
                                        "type": "paragraph",
                                        "content": [
                                            {
                                                "type": "text",
                                                "text": "Dynamic issue description based on provided data."
                                            }
                                        ]
                                    },
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
                                    },
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
                                    },
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
                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Host Name"}]}]},
                                                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "IP Address"}]}]}
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
                                            ],
                                            *[
                                                {
                                                    "type": "tableRow",
                                                    "content": [
                                                        {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": srv["host_name"]}]}]},
                                                        {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": srv["ip_address"]}]}]}
                                                    ]
                                                }
                                                for srv in servers
                                            ]
                                        ]
                                    },
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
                                    },
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


                    response = requests.post(jira_url, data = json.dumps(combined_data), headers=headers, auth=HTTPBasicAuth(username, password))
                    




    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

    finally:
        if connection.is_connected():
            connection.close()
    

def start_scheduler():
    scheduler = BackgroundScheduler()
    # scheduler.add_job(freshservice_call_create_ticket, IntervalTrigger(minutes=90))
    # scheduler.add_job(updateExploitsAndPatchesForFreshservice, IntervalTrigger(minutes=180))
    # scheduler.add_job(jira_call_create_ticket, IntervalTrigger(minutes=180))
    scheduler.start()
