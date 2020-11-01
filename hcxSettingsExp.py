### Package Imports ####
import requests
import json
import time
from requests.auth import HTTPBasicAuth
import webbrowser

### Get On-Prem HCX Details ###
hcx_username = 'cloudadmin@vmc.local'
hcx_password = 'abc5467wR*jR-FC'
hcxmgr_fqdn = 'hcx.sddc-54-14-123-54.vmwarevmc.com'

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
sitepairjson = json.loads(sitepairresp.text)
print("Site Pairing Details: "+sitepairresp.text)
hcxfile.write(sitepairresp.text)


### Get HCX Network Profiles ###
nwprofileurl = 'https://%s/hybridity/api/networks' %(hcxmgr_fqdn)

headers = {'Accept': 'application/json','Content-Type': 'application/json','x-hm-authorization': authtoken}
payload = {}
nwprofileresp = requests.get(nwprofileurl,headers=headers,data=payload)
nwprofilejson = json.loads(nwprofileresp.text)
print("Network Profiles: "+nwprofileresp.text)
hcxfile.write(nwprofileresp.text)
### Get HCX Compute Profiles ###

compprofileurl = 'https://%s/hybridity/api/interconnect/computeProfiles' %(hcxmgr_fqdn)

headers = {'Accept': 'application/json','Content-Type': 'application/json','x-hm-authorization': authtoken}
payload = {}
compprofileresp = requests.get(compprofileurl,headers=headers,data=payload)
compprofilejson = json.loads(compprofileresp.text)
print("Compute Profiles: "+compprofileresp.text)
hcxfile.write(compprofileresp.text)
### Get HCX Service Mesh Details ###

srvmeshurl = 'https://%s/hybridity/api/interconnect/serviceMesh' %(hcxmgr_fqdn)

headers = {'Accept': 'application/json','Content-Type': 'application/json','x-hm-authorization': authtoken}
payload = {}
srvmeshresp = requests.get(srvmeshurl,headers=headers,data=payload)
srvmeshjson = json.loads(srvmeshresp.text)
print("Service Mesh Details: "+srvmeshresp.text)
hcxfile.write(srvmeshresp.text)
hcxfile.close()