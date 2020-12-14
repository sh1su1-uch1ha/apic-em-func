from apic_em_func import *
from tabulate import *
from time import sleep
from re import findall
from requests import post
from requests import get

import json


def get_path_data_tracer():
    while True:
        s_ip = input("Please input source IP address of the path trace -> ")
        ip_check_source = findall(
            "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",
            s_ip)

        d_ip = input("Please input destination IP address of the path trace -> ")
        ip_check_destination = findall(
            "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",
            d_ip)
        if not ip_check_source or s_ip not in getApi.hosts_dict['hosts_ip']:
            print("Invalid IP - " + str(s_ip) + " - Network does not have this ip address \n"
                                                "You must input correct ip address of source\n"
                                                "Enter Ctrl+C for exit")
        elif not ip_check_destination or d_ip not in getApi.hosts_dict['hosts_ip']:
            print("Invalid IP - " + str(s_ip) + " - Network does not have this ip address \n"
                                                "You must input correct ip address of source\n"
                                                "Enter Ctrl+C for exit")
        else:
            data = {
                "sourceIP": s_ip,
                "destIP":   d_ip
            }
            print("\nSource IP address is : ", data["sourceIP"])
            print("Destination IP address is : ", data["destIP"])
            print("\n")
            break
    return data


devices_dict = {'devices_ip': [],
                'type': []
                }
hosts_dict = {'hosts_ip': [],
              'type': []
              }
login = input("Please input your login for DevNet Sandbox")
password = input("Please input your password for DevNet Sandbox")
getApi = API_work(devices_dict=devices_dict,
                  hosts_dict=hosts_dict,
                  login=login,
                  password=password)
requests.packages.urllib3.disable_warnings()

api_url = "https://devnetsbx-netacad-apicem-3.cisco.com/api/v1/flow-analysis"

ticket = getApi.get_ticket()

head = {"content-type": "application/json",
        "X-Auth-Token": ticket
        }
answer = input("Would you like to see hosts of network? (y/n)")
if answer.lower() == 'y':
    print("\n\nList of hosts on the network")
    getApi.print_hosts()

answer = input("\nWould you like to see devices of network? (y/n)")
if answer.lower() == 'y':
    print("\n\nList of devices on the network")
    getApi.print_devices()
    print("\n\n")

# Section 4

path_data = get_path_data_tracer()
path = json.dumps(path_data)
resp = post(api_url, path, headers=head, verify=False)
resp_json = resp.json()
flowAnalysisId = resp_json["response"]["flowAnalysisId"]
print("\nFlow analysis ID : ", flowAnalysisId)

status = " "
check_url = api_url + "/" + flowAnalysisId
check = 0
resp = get(check_url, headers=head, verify=False)
resp_json = resp.json()
while status != "COMPLETED":
    status = resp_json["response"]["request"]["status"]
    print("Requests status is : ", status)
    if status == 'FAILED':
        raise Exception("Problem with Path Trace - Failed")
    sleep(1)
    check += 1
    if check == 15:
        raise Exception("Problem with Path Trace - You was waiting for 15s.")

path_source = resp_json["response"]["networkElementsInfo"][0]
path_dest = resp_json["response"]["networkElementsInfo"][-1]
networkElementsInfo = resp_json["response"]["networkElementsInfo"]

way = []
k = 1
print("\nTrace route From %s to %s\n" % (path_source['ip'],
                                         path_dest['ip']))
for i in networkElementsInfo:
    if i['type'] == 'wired' or i['type'] == 'wireless':
        device = [
            k,
            'host',
            i['type'],
            i['ip'],
            'UNKNOWN',
            'UNKNOWN']
    elif i['type'] == 'Switches and Hubs':
        device = [
            k,
            i['name'],
            i['type'],
            i['ip'],
            i['ingressInterface']['physicalInterface']['name'],
            i['egressInterface']['physicalInterface']['name']
        ]
    else:
        device = [
            k,
            i['name'],
            i['type'],
            i['ip'],
            'UNKNOWN',
            'UNKNOWN']
    way.append(device)
    k += 1

table_header = ["№", "Name", "Type", "IP", "Ingress int", "Egress int"]
print(tabulate(way, table_header))
