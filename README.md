[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/tekgourou/Duo_User-Context-Mapping_to_FMC)

### Sharing Duo User Context (IP & HostProfile) to Cisco Firepower Management Center
  
This repo contains a Python & Perl scripts to grab User context information, IP & Host profile, from a Duo Security authentification and share this with Cisco FMC.
![image](./diagram.png)
<br/>
![image](./fmc_user_activity.png)
<br/>
![image](./fmc_host_profile.png)

Please contact me at alexandre@argeris.net, if you have any questions or remarks. If you find any bugs, please report them to me, and I will correct them. 
  
### VARIABLES TO MODIFY BEFORE RUNNING THE SCRIPT 
parameters.json need to be modify before running the script. <br/>
![image](./parameters.png)

### How to create a FMC user with API role
Add a new role. <br/>
![image](./fmc_api_role.png)

Add a new user <br/>
![image](./fmc_api_user.png)


### Perl script for Host Input (FMC) communications
This script is based on the AMP4e-to-FMC-Host-Input-Script available on cisco.com <br/>
https://software.cisco.com/download/home/286259687/type/286271057/release/Host%20InputNote <br/>
These files are of 'FMC Host Input API SDK'as-it-is downloaded from CCO without any modifications. <br/>
sf_host_input_agent.pl <br/>
SFCheckPreReq.pm <br/>
SFHIclient.pm <br/>
SFHIlog.pm <br/>
SFHostInputAgent.pm <br/>
SFPkcs12.pm <br/>
InputPlugins\csv.pm <br/>

### CLONING THE REPO 
git clone https://github.com/tekgourou/Duo_User-Context-Mapping_to_FMC.git <br/>
cd Duo_User-Context-Mapping_to_FMC/scripts <br/>
python3 -m venv venv <br/>
source venv/bin/activate <br/>
pip3 install -r requirements.txt <br/>

### Prerequisites
This tool use python to establish communications with Duo Admin API and pull the context informations for all athentifications. The REST VDI API is use to share Duo User/IP mapping to FMC. <br/>
Then the tool uses perl to establish communications with FMC to add host profile collected earlier to the Hostprofile in FMC. <br/>

### Python Modules
duo_client (https://pypi.org/project/duo-client/)<br/>
requests <br/>
tinydb <br/>

### Duo Admin API key
You will need to get your Duo Admin API key from the Duo Admin Portal.
https://duo.com/docs/adminapi

### FMC Host Input API client certificate
File (xxxxxx.pkcs12) generated from FMC, downloaded in this script's local directory.
To generate the certificate, login to FMC Web GUI and navigate to System -> Integrations -> Host Input Client-> CreateClient->give the IP address of your HOST and DO NOT GIVE a password-> Save. Download the pkcs12file in this script's local directory.


### Running this script
Before running the following command ensure that all prerequisites are met and run it in the script directory loaded.
To run the tool simply execute: <br/>

python3.6 Duo_to_FMC.py <br/>

My suggestion is to run the script with crontab (linux) or Task Scheduler (Microsoft) every 5 minutes. <br/>

All the activities of the script are logged to a file called AUDIT.log file. The file is not over-written, only appended. This includes all INFO and ERROR messages.

![image](./AUDIT_log.png)
