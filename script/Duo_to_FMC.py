#!/bin/env python

'''
PURPOSE:
THIS SCRIPT IMPORTS ALL THE OPERATING SYSTEMS INFORMATION FROM DUO CONSOLE USING THE DUO ADMIN API,
    PRINTS THE OUTPUT TO A CSV AND THEN IMPORTS THE CSV INTO FIREPOWER MANAGEMENT CENTER USING THE HOST INPUT API OF FMC.

DEPENDENCIES / REQUIREMENTS:
1- PYTHON 3.6
2- PERL 5
3- ACCOUNT ON DUO PUBLIC CLOUD AND AN API KEY GENERATED.
4- FIREPOWER MANAGEMENT CENTER (FMC) 6.x +
5- 'requests' MODULE, THAT CAN BE INSTALLED BY EXECUTING THE COMMAND "python -m pip install requests"
5- 'duo_client' MODULE, THAT CAN BE INSTALLED BY EXECUTING THE COMMAND "python -m pip install duo_client"
6- UPDATE THE 'parameters.json' FILE WITH THE DETAILS BEFORE EXECUTING THIS SCRIPT
7- TCP PORT 443 TO DUO API CLOUD.
8- TCP PORT 8307 TO FMC
9- FMC HOST INPUT API CLIENT CERTIFICATE FILE (xxxxxx.pkcs12) GENERATED FROM FMC, DOWNLOADED IN THIS SCRIPT'S LOCAL DIRECTORY.
     TO GENERATE THE CERTIFICATE, LOGIN TO FMC WEB GUI AND NAVIGATE TO SYSTEM -> INTEGRATIONS -> HOST INPUT CLIENT -> CREATE CLIENT
     -> HOSTNAME IS THE IP OF THE HOST RUNNING THIS SCRIPT AND ***NO PASSWORD*** -> DOWNLOAD THE PKCS12 FILE IN THIS SCRIPT'S LOCAL DIRECTORY

This script is based on the AMP4Endpoint Host Input for FMC. Modified by Alexandre Argeris (aargeris@cisco.com)

NOTE:
All Cisco software is subject to the Supplemental End User License Agreements (SEULA) located at https://www.cisco.com/c/en/us/about/legal/cloud-and-software/software-terms.html
'''

import json
import sys
import subprocess
import logging
import os
import duo_client
import time
import requests
from datetime import datetime
from datetime import date
from tinydb import TinyDB, Query

print('##########################################################')
print('#       Duo - FMC user / endpoint context sharing        #')
print('#            Production use at your own risk             #')
print('#       aargeris@cisco.com, alexandre@argeris.net        #')
print('#        Run this script once to detect any error        #')
print('#             then put it in your crontab                #')
print('##########################################################')
print()

auditlogfile = "AUDIT.log"

# Start Log File Handler
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.FileHandler(auditlogfile)
datefmt = '[%Y-%m-%d %H:%M:%S]'
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt)
handler.setFormatter(formatter)
logger.addHandler(handler)

# Import variables to get configuration
logger.info("###############################################################################")
logger.info("###############################################################################")
logger.info("Starting execution of the script")
config = ''
try:
    config = json.loads(open("parameters.json").read())
    logger.info("Found the parameters file - 'parameters.json'. Loading in parameters now....")
except Exception as err:
    logger.error(
        "ERROR in reading the 'parameters.json' file or the file does not exist. So exiting!  Below is the exact exception message.")
    print(
        "ERROR in reading the 'parameters.json' file or the file does not exist. So exiting!  Below is the exact exception message.")
    logger.error(str(err))
    print(str(err))
    logger.error("Check out the sample 'parameters.json' file for example....")
    print("Check out the sample 'parameters.json' file for example....")
    sys.exit()

csv = open("./hostinputcsv.txt", "w")

# FMC TS AGENT API PATH
api_auth_path = "/api/fmi_platform/v1/identityauth/generatetoken"
api_path = "/api/identity/v1/identity/useridentity"

# Create dictionary of variables
var = {
    "Duo_skey": config["Duo_skey"],
    "Duo_ikey": config["Duo_ikey"],
    "Duo_API_hostname": config["Duo_API_hostname"],
    "Record_return_time": config["Record_return_time"],
    "Duo_user_timeout": config["Duo_user_timeout"],
    "FMC_ipaddress": config["FMC_ipaddress"],
    "FMC_host_vuln_db_overwrite_OR_update": config["FMC_host_vuln_db_overwrite_OR_update"],
    "push_changes_to_fmc": config["push_changes_to_fmc"],
    "FMC_user": config["FMC_user"],
    "FMC_password": config["FMC_password"],
    "Domain": config["Domain"],
}

# Check to make sure there is data in the parameters
for key in var.keys():
    value = var[key]
    if value != "":
        if key == 'Duo_skey':
            logger.info("Parameters {} is {}".format(key, '*******************'))
        else:
            logger.info("Parameters {} is {}".format(key, value))
    else:
        logger.error("Missing Value for the Parameter {}.... So exiting!".format(key, value))
        print("Missing Value for the Parameter {}.... So exiting!".format(key, value))
        sys.exit()

if 'Duo_skey' not in var.keys():
    logger.error(
        "Missing the Parameter - 'Duo_skey'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
    print(
        "Missing the Parameter - 'Duo_skey'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
    sys.exit()
if 'Duo_ikey' not in var.keys():
    logger.error(
        "Missing the Parameter - 'Duo_ikey'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
    print(
        "Missing the Parameter - 'Duo_ikey'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
    sys.exit()
if 'Duo_API_hostname' not in var.keys():
    logger.error(
        "Missing the Parameter - 'Duo_API_hostname'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
    print(
        "Missing the Parameter - 'Duo_API_hostname'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
    sys.exit()
# Check that var["A4E_group_names"] is a list
if 'FMC_ipaddress' not in var.keys():
    logger.error(
        "Missing the Parameter - 'FMC_ipaddress'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
    print(
        "Missing the Parameter - 'FMC_ipaddress'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
    sys.exit()
if 'FMC_host_vuln_db_overwrite_OR_update' not in var.keys():
    logger.error(
        "Missing the Parameter - 'FMC_host_vuln_db_overwrite_OR_update'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
    print(
        "Missing the Parameter - 'FMC_host_vuln_db_overwrite_OR_update'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
    sys.exit()
if var['FMC_host_vuln_db_overwrite_OR_update'] != "overwrite" and var[
    'FMC_host_vuln_db_overwrite_OR_update'] != "update":
    logger.error(
        "Parameter - 'FMC_host_vuln_db_overwrite_OR_update' can be either set to \"update\" or \"overwrite\". Any other value is not allowed... So exiting!  Check out the sample 'parameters.json' file for example.... ")
    print(
        "Parameter - 'FMC_host_vuln_db_overwrite_OR_update' can be either set to \"update\" or \"overwrite\". Any other value is not allowed... So exiting!  Check out the sample 'parameters.json' file for example.... ")
    sys.exit()
if 'push_changes_to_fmc' not in var.keys():
    logger.error(
        "Missing the Parameter - 'push_changes_to_fmc'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
    print(
        "Missing the Parameter - 'push_changes_to_fmc'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
    sys.exit()

logger.info("Parameter check complete")

db_file = 'db_Duo_users_{}.json'.format(var["FMC_ipaddress"])
db = TinyDB(db_file)

# DELETE Duo USER MAPPING on FMC after TIMEOUT
def DEL_USER_FMC_TS_AGENT_API(sessionID):
    # Allow connection to server with a selfsigned certificate
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    #API request
    r = None
    headers = {'Content-Type': 'application/json'}
    auth_url = 'https://{}{}'.format(var['FMC_ipaddress'],api_auth_path)
    try:
        r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(var['FMC_user'],var['FMC_password']), verify=False)
        auth_headers = r.headers
        auth_token = auth_headers.get('X-auth-access-token', default=None)
        if auth_token == None:
            print("auth_token not found. Exiting...")

            sys.exit()
    except Exception as err:
        print("Error in generating auth token --> " + str(err))
        sys.exit()

    headers['X-auth-access-token'] = auth_token
    url = 'https://{}{}/{}'.format(var['FMC_ipaddress'],api_path,sessionID)
    if (url[-1] == '/'):
        url = url[:-1]

    try:
        r = requests.delete(url, headers=headers, verify=False)
        status_code = r.status_code
        resp = r.text
        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        today = date.today()
        if status_code == 200 or status_code == 201 or status_code == 202:
            #json_resp = json.loads(resp)
            #print("{} {}, API Post was successful, DELETING SessionID {} from FMC and {}".format(today, current_time, sessionID, db_file))
            db.remove(Query()['SessionID'] == sessionID)
        else:
            r.raise_for_status()
            print("{} {} : Error occurred in POST --> {}".format(today, current_time, resp))
    except requests.exceptions.HTTPError as err:
        print("{} {} : Error in connection --> {}".format(today, current_time, str(err)))
    finally:
        if r: r.close()

def search_log_based_on_time_to_delete_users_mapping():
    timeout_unix_timestamp = (int(time.time())) - int(var['Duo_user_timeout'])
    log = db.search(Query().TIME < timeout_unix_timestamp)
    for line in log:
        sessionID = line['SessionID']
        #print ('{} sessionID will be delete'.format(sessionID))
        DEL_USER_FMC_TS_AGENT_API(sessionID)

# CALLING FONCTION to look for SessionID to delete on FMC based on timeout
search_log_based_on_time_to_delete_users_mapping()

def duo_search_result_logs(host,skey,ikey, return_record_time):
    # GET Unix Timestamp
    last_unix_timestamp = (int(time.time())) - return_record_time
    admin_api = duo_client.Admin(ikey=ikey,skey=skey,host=host)
    logs = admin_api.get_authentication_log(mintime=last_unix_timestamp)
    list_msg = []
    for data in logs:
        data_auth_result = data['result']
        if 'SUCCESS' == data_auth_result:
            list_msg.append(data)
    if len(list_msg) == 0:
        #print ('No logs found in your DUO environnement')
        sys.exit()
    return list_msg

duo_list = duo_search_result_logs(var["Duo_API_hostname"], var["Duo_skey"], var["Duo_ikey"], int(var["Record_return_time"]))

#POST Duo User IP mapping to FMC using TS Agent API
def ADD_USER_FMC_TS_AGENT_API(ip,username, domain, isotime, unix_timestamp):
    # Allow connection to server with a selfsigned certificate
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    #API request
    r = None
    headers = {'Content-Type': 'application/json'}
    auth_url = 'https://{}{}'.format(var['FMC_ipaddress'],api_auth_path)
    try:
        r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(var['FMC_user'],var['FMC_password']), verify=False)
        auth_headers = r.headers
        auth_token = auth_headers.get('X-auth-access-token', default=None)
        if auth_token == None:
            print("auth_token not found. Exiting...")

            sys.exit()
    except Exception as err:
        print("Error in generating auth token --> " + str(err))
        sys.exit()

    # Building the access token and URL
    headers['X-auth-access-token'] = auth_token
    url = 'https://{}{}'.format(var['FMC_ipaddress'],api_path)
    if (url[-1] == '/'):
        url = url[:-1]

    # Bulding the json
    post_data = "{\n\n\"user\": \"" + username + "\",\n\n\"srcIpAddress\": \"" + ip + "\",\n\n\"agentInfo\": \"Duo\",\n\n\"timestamp\": \"" + isotime + "\",\n\n\"domain\": \"" + domain + "\"\n\n}\n\n"
    #print ('User: {}, domain: {}, IP address: {}'.format(username, domain, ip))
    # Sending the resquest to add user-ip mapping
    try:
        r = requests.post(url, data=post_data, headers=headers, verify=False)
        status_code = r.status_code
        resp = r.text
        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        today = date.today()
        if status_code == 201 or status_code == 202:
            json_resp = json.loads(resp)
            ID = json_resp["id"]
            db.insert({'TIME': unix_timestamp, 'Username': username, 'DeviceIP': ip, 'Domain': domain, 'SessionID': ID})
        else:
            r.raise_for_status()
            print("{} {} : Error occurred in POST --> {}".format(today, current_time, resp))

    except requests.exceptions.HTTPError as err:
        print("Error in connection --> " + str(err))
    finally:
        if r: r.close()

def UPDATE_USER_FMC_TS_AGENT_API(ip,username, domain, isotime, unix_timestamp):
    # Allow connection to server with a selfsigned certificate
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    #API request
    r = None
    headers = {'Content-Type': 'application/json'}
    auth_url = 'https://{}{}'.format(var['FMC_ipaddress'],api_auth_path)
    try:
        r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(var['FMC_user'],var['FMC_password']), verify=False)
        auth_headers = r.headers
        auth_token = auth_headers.get('X-auth-access-token', default=None)
        if auth_token == None:
            print("auth_token not found. Exiting...")

            sys.exit()
    except Exception as err:
        print("Error in generating auth token --> " + str(err))
        sys.exit()

    # Building the access token and URL
    headers['X-auth-access-token'] = auth_token
    url = 'https://{}{}'.format(var['FMC_ipaddress'],api_path)
    if (url[-1] == '/'):
        url = url[:-1]

    # Bulding the json
    post_data = "{\n\n\"user\": \"" + username + "\",\n\n\"srcIpAddress\": \"" + ip + "\",\n\n\"agentInfo\": \"Duo\",\n\n\"timestamp\": \"" + isotime + "\",\n\n\"domain\": \"" + domain + "\"\n\n}\n\n"
    #print ('User: {}, domain: {}, IP address: {}'.format(username, domain, ip))
    # Sending the resquest to add user-ip mapping
    try:
        r = requests.post(url, data=post_data, headers=headers, verify=False)
        status_code = r.status_code
        resp = r.text
        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        today = date.today()
        if status_code == 201 or status_code == 202:
            json_resp = json.loads(resp)
            ID = json_resp["id"]
            db.update({'TIME': unix_timestamp},(Query()['Username'] == username) & (Query()['DeviceIP'] == ip) & (Query()['Domain'] == domain))
        else:
            r.raise_for_status()
            print("{} {} : Error occurred in POST --> {}".format(today, current_time, resp))

    except requests.exceptions.HTTPError as err:
        print("Error in connection --> " + str(err))
    finally:
        if r: r.close()


#Prepare the CSV for FMC host input
csv.write("SetSource,Cisco Duo Security\n")
#csv.write("AddHostAttribute,{},{}\n".format('Duo_email', 'text'))
#csv.write("AddHostAttribute,{},{}\n".format('Duo_Trusted_Endpoint_Status', 'text'))
#csv.write("AddHostAttribute,{},{}\n".format('Duo_Auth_Location', 'text'))

def add_host_to_csv(ip, opersys, opersys_version, app, app_version, duo_app ):
    csv.write("AddHost,{}\n".format(ip))
    if opersys == ("Windows"):
        csv.write("SetOS,{},Microsoft,{},\"{}\"\n".format(ip, opersys, opersys_version))
    if opersys == ("Mac OS X"):
        csv.write("SetOS,{},Apple,{},\"{}\"\n".format(ip, "Mac OSX", opersys_version))
    if opersys == ("iOS"):
        csv.write("SetOS,{},Apple,{},\"{}\"\n".format(ip, "iOS", opersys_version))
    if opersys == ("None"):
        csv.write("SetOS,{},pending,{},\"{}\"\n".format(ip, "pending", "pending"))
    else:
        csv.write("SetOS,{},{},{},\"{}\"\n".format(ip, opersys, opersys, opersys_version))
    csv.write("AddClientApp,{},{},{},\"{}\"\n".format(ip, app, 'Unknown', app_version))
    csv.write("AddClientApp,{},{},{},\"{}\"\n".format(ip, duo_app, 'Duo App', 'unknown'))
    # csv.write("SetAttributeValue,{},{},{}\n".format(ip, 'Duo_email', duo_email))
    # csv.write("SetAttributeValue,{},{},{}\n".format(ip, 'Duo_Trusted_Endpoint_Status', duo_trusted_endpoint_status))


# Get USER / IP / Endpoint informations from Duo
for line in duo_list:
    connector_guid = line['device']
    isactive = True
    ip = line['ip']
    opersys = line['access_device']['os']
    opersys_version = line['access_device']['os_version']
    app = line['access_device']['browser']
    app_version = line['access_device']['browser_version']
    duo_app = line['integration']
    username = line['username']
    unix_timestamp = line['timestamp']
    isotime = line['isotimestamp']
    if '@' in username:
        domain = username.split('@')[1]
        username = username.split('@')[0]
    else:
        domain = var["Domain"]
    #duo_trusted_endpoint_status = line['access_device']['trusted_endpoint_status']
    #duo_email = line['email']

    if db.get((Query()['Username'] == username) & (Query()['DeviceIP'] == ip) & (Query()['Domain'] == domain)) is None:
        # ADDING Duo User IP MAPPING to FMC
        ADD_USER_FMC_TS_AGENT_API(ip, username, domain, isotime, unix_timestamp)
        # ADDING ENDPOINT CONTEXT to CSV
        add_host_to_csv(ip, opersys, opersys_version, app, app_version, duo_app)
        #print('{}, {}, {}, {}, {}, {}, {}'.format(username, ip, opersys, opersys_version, app, app_version, duo_app))

    elif db.get((Query()['TIME'] == unix_timestamp) & (Query()['Username'] == username) & (Query()['DeviceIP'] == ip) & (Query()['Domain'] == domain)) is True:
        print ()

    elif db.get((Query()['Username'] == username) & (Query()['DeviceIP'] == ip) & (Query()['Domain'] == domain)) is True:
        # UPDATE Duo User IP MAPPING to FMC
        UPDATE_USER_FMC_TS_AGENT_API(ip, username, domain, isotime, unix_timestamp)
        # ADDING ENDPOINT CONTEXT to CSV
        add_host_to_csv(ip, opersys, opersys_version, app, app_version, duo_app)
        # print('{}, {}, {}, {}, {}, {}, {}'.format(username, ip, opersys, opersys_version, app, app_version, duo_app))


    #else:
        #print('Session found for ' + username + ' using IP ' + ip + ' Domain ' + domain + 'TIME ' + str(unix_timestamp) + ' in DB')

#SENDING CSV File to FMC via HOST INPUT API
if var['FMC_host_vuln_db_overwrite_OR_update'] == "overwrite":
    csv.write("ScanFlush")
else:
    csv.write("ScanUpdate")

csv.close()
logger.info("Completed the Parsing of the events and wrote the information to the CSV file")

if not var["push_changes_to_fmc"]:
    logger.info("Not supposed to push any changes to FMC as per the parameters in 'parameters.json'...  So exiting!")
    print("Not supposed to push any changes to FMC as per the parameters in 'parameters.json'...  So exiting!")
    sys.exit()
else:
    # Call the Perl Host Input SDK client for the Host Input
    logger.info("Calling the PERL client of FMC Host Input SDK to push the CSV details into FMC")

    perl_log_filename = ".HostInput.log"
    if os.path.exists(perl_log_filename):
        try:
            os.remove(perl_log_filename)
        except:
            pass

    logger.info("COMMAND:-" + " perl" + " sf_host_input_agent.pl" + " -server={}".format(
        var["FMC_ipaddress"]) + " -level=3" + " -logfile={}".format(
        perl_log_filename) + " -plugininfo=hostinputcsv.txt" + " csv" + " -runondc=n")

    pipe = subprocess.call(["perl", "sf_host_input_agent.pl", "-server={}".format(var["FMC_ipaddress"]), "-level=3",
                            "-logfile={}".format(perl_log_filename), "-plugininfo=hostinputcsv.txt", "csv",
                            "-runondc=n"])

    logger.info("The output of the script is saved in a seperate file. Copying the content of that file here as-it-is")

    try:
        with open(perl_log_filename) as f:
            output = f.read()
            logger.info("\n" + output)
            f.close()
        os.remove(perl_log_filename)
    except:
        logger.error(
            "Could not open the " + perl_log_filename + " file, so probably the PERL script execution might have failed")
        print(
            "Could not open the " + perl_log_filename + " file, so probably the PERL script execution might have failed")
        sys.exit()

print("The output of the script is appended to '" + auditlogfile + "' file")