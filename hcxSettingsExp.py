### Package Imports ####
import requests
import json
import time
from requests.auth import HTTPBasicAuth
import webbrowser

### Get On-Prem HCX Details ###
hcx_username = 'cloudadmin@vmc.local'
hcx_password = '3dfgvJ2ywR*jR-BCDRT'
hcxmgr_fqdn = 'hcx.sddc-53-14-123-91.vmwarevmc.com'

print("Please hit Enter to accept the defaults.")

hcxmgr_fqdn = input ("HCX Manager FQDN ["+hcxmgr_fqdn+"]:") or hcxmgr_fqdn
hcx_username = input("HCX Username ["+hcx_username+"]:") or hcx_username
hcx_password = input("Enter HCX Password:") or hcx_password


### Get Authorized for HCX API access ###
payload = {}
payload["username"] =  hcx_username
payload["password"] =  hcx_password
json_data = json.dumps(payload)
authurl = 'https://%s/hybridity/api/sessions' %(hcxmgr_fqdn)
headers = {'Accept': 'application/json','Content-Type': 'application/json'}
authresp = requests.post(authurl,headers=headers,data=json_data)
print (json.loads(authresp.text))
authtoken = authresp.headers["x-hm-authorization"]

print("Auth Token: "+authresp.headers["x-hm-authorization"])

hcxfile = open("hcxExp.json", "a+")
### Get HCX Site Pairing Details ###
sitepairurl = 'https://%s/hybridity/api/cloudConfigs' %(hcxmgr_fqdn)

headers = {'Accept': 'application/json','Content-Type': 'application/json','x-hm-authorization': authtoken}
payload = {}
sitepairresp = requests.get(sitepairurl,headers=headers,data=payload)
sitepairresp = "{\"sitePair\": "+sitepairresp.text+","
print(sitepairresp)
hcxfile.write(sitepairresp)


### Get HCX Network Profiles ###
nwprofileurl = 'https://%s/hybridity/api/networks' %(hcxmgr_fqdn)

headers = {'Accept': 'application/json','Content-Type': 'application/json','x-hm-authorization': authtoken}
payload = {}
nwprofileresp = requests.get(nwprofileurl,headers=headers,data=payload)
nwprofileresp = "\"networkProfile\": "+nwprofileresp.text+","
print("Network Profiles: "+nwprofileresp)
hcxfile.write(nwprofileresp)
### Get HCX Compute Profiles ###

compprofileurl = 'https://%s/hybridity/api/interconnect/computeProfiles' %(hcxmgr_fqdn)

headers = {'Accept': 'application/json','Content-Type': 'application/json','x-hm-authorization': authtoken}
payload = {}
compprofileresp = requests.get(compprofileurl,headers=headers,data=payload)
compprofileresp = "\"computeProfile\": "+compprofileresp.text+","
print("Compute Profiles: "+compprofileresp)
hcxfile.write(compprofileresp)
### Get HCX Service Mesh Details ###

srvmeshurl = 'https://%s/hybridity/api/interconnect/serviceMesh' %(hcxmgr_fqdn)

headers = {'Accept': 'application/json','Content-Type': 'application/json','x-hm-authorization': authtoken}
payload = {}
srvmeshresp = requests.get(srvmeshurl,headers=headers,data=payload)
srvmeshresp = "\"serviceMesh\": "+srvmeshresp.text+"}"
print("Service Mesh Details: "+srvmeshresp)
hcxfile.write(srvmeshresp)
hcxfile.close()
