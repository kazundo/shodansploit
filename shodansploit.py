#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import json
import os
import signal

# shodansploit v1.0.0

searchploit_txt = """
      _               _                       _       _ _
  ___| |__   ___   __| | __ _ _ __  ___ _ __ | | ___ (_) |_
 / __| '_ \ / _ \ / _` |/ _` | '_ \/ __| '_ \| |/ _ \| | __|
 \__ \ | | | (_) | (_| | (_| | | | \__ \ |_) | | (_) | | |_
 |___/_| |_|\___/ \__,_|\__,_|_| |_|___/ .__/|_|\___/|_|\__|
                                       |_|            v1.2.0
	Author : Ismail Tasdelen
	GitHub : github.com/ismailtasdelen
      Linkedin : linkedin.com/in/ismailtasdelen
       Twitter : twitter.com/ismailtsdln
"""
###
shodansploit_menu_txt = """
[1] GET > /shodan/host/{ip}
[2] GET > /shodan/host/count
[3] GET > /shodan/host/search
[4] GET > /shodan/host/search/tokens
[5] GET > /shodan/ports

[6] GET > /shodan/exploit/author
[7] GET > /shodan/exploit/cve
[8] GET > /shodan/exploit/msb
[9] GET > /shodan/exploit/bugtraq-id
[10] GET > /shodan/exploit/osvdb
[11] GET > /shodan/exploit/title
[12] GET > /shodan/exploit/description
[13] GET > /shodan/exploit/date
[14] GET > /shodan/exploit/code
[15] GET > /shodan/exploit/platform
[16] GET > /shodan/exploit/port

[17] GET > /dns/resolve
[18] GET > /dns/reverse
[19] GET > /labs/honeyscore/{ip}

[20] GET > /account/profile
[21] GET > /tools/myip
[22] GET > /tools/httpheaders
[23] GET > /api-info

[24] Exit
"""

if os.path.exists("./api.txt") and os.path.getsize("./api.txt") > 0:
    with open('api.txt', 'r') as file:
        shodan_api = file.readline().rstrip('\n')
else:
    shodan_api = input('[*] Please enter a valid Shodan.io API Key: ')
    with open('api.txt', 'w') as file:
        file.write(shodan_api)
    print('[~] File written: ./api.txt')

def signal_handler(signal, frame):
    print("\nExiting...\n")
    exit(0)

def make_request(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        parsed = response.json()
        print(json.dumps(parsed, indent=2, sort_keys=True))
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
    except json.JSONDecodeError:
        print("Failed to parse response as JSON")

def shodan_host_ip():
    host_ip = input("Shodan Host Search : ")
    url = f"https://api.shodan.io/shodan/host/{host_ip}?key={shodan_api}"
    make_request(url)

def shodan_count_search():
    host_search = input("Shodan Host Search : ")
    url = f"https://api.shodan.io/shodan/host/count?key={shodan_api}&query={host_search}"
    make_request(url)

def host_search():
    host_search = input("Shodan Host Search : ")
    url = f"https://api.shodan.io/shodan/host/search?key={shodan_api}&query={host_search}"
    make_request(url)

def shodan_token_search():
    token_search = input("Shodan Token Search : ")
    url = f"https://api.shodan.io/shodan/host/search/tokens?key={shodan_api}&query={token_search}"
    make_request(url)

def shodan_ports():
    url = f"https://api.shodan.io/shodan/ports?key={shodan_api}"
    make_request(url)

def shodan_dns_lookup():
    hostnames = input("DNS Lookup : ")
    url = f"https://api.shodan.io/dns/resolve?hostnames={hostnames}&key={shodan_api}"
    make_request(url)

def shodan_dns_reverse():
    ips = input("DNS Reverse : ")
    url = f"https://api.shodan.io/dns/reverse?ips={ips}&key={shodan_api}"
    make_request(url)

def shodan_honeyscore():
    honeypot = input("DNS Reverse : ")
    url = f"https://api.shodan.io/labs/honeyscore/{honeypot}?key={shodan_api}"
    make_request(url)

def shodan_profile():
    url = f"https://api.shodan.io/account/profile?key={shodan_api}"
    make_request(url)

def shodan_myip():
    url = f"https://api.shodan.io/tools/myip?key={shodan_api}"
    make_request(url)

def shodan_httpheaders():
    url = f"https://api.shodan.io/tools/httpheaders?key={shodan_api}"
    make_request(url)

def shodan_api_info():
    url = f"https://api.shodan.io/api-info?key={shodan_api}"
    make_request(url)

def shodan_exploit_author():
    exploit_author = input("Exploit Author : ")
    url = f"https://exploits.shodan.io/api/search?query=author:{exploit_author}&key={shodan_api}"
    make_request(url)

def shodan_exploit_cve():
    exploit_cve = input("Exploit CVE : ")
    url = f"https://exploits.shodan.io/api/search?query=cve:{exploit_cve}&key={shodan_api}"
    make_request(url)

def shodan_exploit_msb():
    exploit_msb = input("Exploit Microsoft Security Bulletin ID : ")
    url = f"https://exploits.shodan.io/api/search?query=msb:{exploit_msb}&key={shodan_api}"
    make_request(url)

def shodan_exploit_bid():
    exploit_bid = input("Exploit Bugtraq ID : ")
    url = f"https://exploits.shodan.io/api/search?query=bid:{exploit_bid}&key={shodan_api}"
    make_request(url)

def shodan_exploit_osvdb():
    exploit_osvdb = input("Exploit Open Source Vulnerability Database ID : ")
    url = f"https://exploits.shodan.io/api/search?query=osvdb:{exploit_osvdb}&key={shodan_api}"
    make_request(url)

def shodan_exploit_title():
    exploit_title = input("Exploit Title : ")
    url = f"https://exploits.shodan.io/api/search?query=title:{exploit_title}&key={shodan_api}"
    make_request(url)

def shodan_exploit_description():
    exploit_description = input("Exploit Description : ")
    url = f"https://exploits.shodan.io/api/search?query=description:{exploit_description}&key={shodan_api}"
    make_request(url)

def shodan_exploit_date():
    exploit_date = input("Exploit Date : ")
    url = f"https://exploits.shodan.io/api/search?query=date:{exploit_date}&key={shodan_api}"
    make_request(url)

def shodan_exploit_code():
    exploit_code = input("Exploit Code : ")
    url = f"https://exploits.shodan.io/api/search?query=code:{exploit_code}&key={shodan_api}"
    make_request(url)

def shodan_exploit_platform():
    exploit_platform = input("Exploit Platform : ")
    url = f"https://exploits.shodan.io/api/search?query=platform:{exploit_platform}&key={shodan_api}"
    make_request(url)

def shodan_exploit_port():
    exploit_port = input("Exploit Port : ")
    url = f"https://exploits.shodan.io/api/search?query=port:{exploit_port}&key={shodan_api}"
    make_request(url)

def shodansploit_exit():
    exit(0)

# Mapping choices to functions
menu_options = {
    1: shodan_host_ip,
    2: shodan_count_search,
    3: host_search,
    4: shodan_token_search,
    5: shodan_ports,
    6: shodan_exploit_author,
    7: shodan_exploit_cve,
    8: shodan_exploit_msb,
    9: shodan_exploit_bid,
    10: shodan_exploit_osvdb,
    11: shodan_exploit_title,
    12: shodan_exploit_description,
    13: shodan_exploit_date,
    14: shodan_exploit_code,
    15: shodan_exploit_platform,
    16: shodan_exploit_port,
    17: shodan_dns_lookup,
    18: shodan_dns_reverse,
    19: shodan_honeyscore,
    20: shodan_profile,
    21: shodan_myip,
    22: shodan_httpheaders,
    23: shodan_api_info,
    24: shodansploit_exit
}

signal.signal(signal.SIGINT, signal_handler)

while True:
    print(searchploit_txt)
    print(shodansploit_menu_txt)

    try:
        choice = int(input("Which option number: ").strip())
        if choice in menu_options:
            menu_options[choice]()
        else:
            print("[✘] Invalid option. Please select a valid number from the menu.")
        input("\nPress the <ENTER> key to continue...")

    except ValueError:
        print("[✘] Please enter a valid number.")
    except Exception as e:
        print(f"[✘] An unexpected error occurred: {e}")
        option = input('[*] Would you like to change API Key? <Y/n>: ').lower()
        if option.startswith('y'):
            shodan_api = input('[*] Please enter valid Shodan.io API Key: ')
            with open('api.txt', 'w') as file:
                file.write(shodan_api)
            print('[~] File written: ./api.txt')
            print('[~] Restarting...')
        else:
            print('[•] Exiting...')
            exit(0)
