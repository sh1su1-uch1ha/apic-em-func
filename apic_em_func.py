import json
import requests
from tabulate import *


class Status_code_exception(Exception):
    def __init__(self, message):
        self.message = message


class API_work(object):

    def __init__(self, devices_dict, hosts_dict, login, password):
        self.devices_dict = devices_dict
        self.hosts_dict = hosts_dict
        self.login = login
        self.password = password
        self.ticket = self.get_ticket()
        self.hosts_json = self.get_hosts()
        self.devices_json = self.get_devices()

    def get_ticket(self):
        requests.packages.urllib3.disable_warnings()
        api_url = "https://devnetsbx-netacad-apicem-3.cisco.com/api/v1/ticket"
        head = {"content-type": "application/json"
                }
        body_json = {"username": self.login,
                     "password": self.password
                     }
        resp = requests.post(api_url, json.dumps(body_json), headers=head, verify=False)
        print("Ticket requests status: ", resp.status_code)
        response_json = resp.json()
        service_ticket = response_json["response"]["serviceTicket"]
        print("Service ticket", service_ticket)
        return service_ticket

    def get_hosts(self):
        api_url = "https://devnetsbx-netacad-apicem-3.cisco.com/api/v1/host"
        ticket = self.ticket
        head = {"content-type": "application/json",
                "X-Auth-Token": ticket
                }
        resp = requests.get(api_url, headers=head, verify=False)
        try:
            print("Status of /host requests: ", resp.status_code)
            if resp.status_code != 200:
                raise Status_code_exception("Status code does not equal 200. Response text:" + resp.text)
        except Status_code_exception as sce:
            print(sce)
        response_json = resp.json()
        for item in response_json["response"]:
            self.hosts_dict['hosts_ip'].append(item["hostIp"])
            self.hosts_dict['type'].append(item["hostType"])
        return response_json

    def print_hosts(self):
        response_json = self.hosts_json
        host_list = []
        for item in response_json["response"]:
            self.hosts_dict['hosts_ip'].append(item["hostIp"])
            self.hosts_dict['type'].append(item["hostType"])
            host = [
                item["hostType"],
                item["hostIp"]
                ]
            host_list.append(host)
        table_header = ["Host Type", "Host IP"]
        print(tabulate(host_list, table_header))

    def get_devices(self):
        api_url = "https://devnetsbx-netacad-apicem-3.cisco.com/api/v1/network-device"
        ticket = self.ticket
        head = {"content-type": "application/json",
                "X-Auth-Token": ticket
                }
        resp = requests.get(api_url, headers=head, verify=False)
        try:
            print("Status of /devices requests: ", resp.status_code)
            if resp.status_code != 200:
                raise Status_code_exception("Status code does not equal 200. Response text:" + resp.text)
        except Status_code_exception as sce:
            print(sce)
        response_json = resp.json()
        for item in response_json["response"]:
            self.devices_dict['devices_ip'].append(item["managementIpAddress"])
            self.devices_dict['type'].append(item["type"])
        return response_json

    def print_devices(self):
        response_json = self.devices_json
        host_list = []
        for item in response_json["response"]:
            host = [
                item["type"],
                item["managementIpAddress"],
                item["upTime"]
            ]
            host_list.append(host)
        table_header = ["Devise Type", "IP", "Up Time"]
        print(tabulate(host_list, table_header))
