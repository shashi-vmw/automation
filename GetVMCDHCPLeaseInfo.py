### Package Imports ####
import requests
import json
import time
from requests.auth import HTTPBasicAuth
import webbrowser

### Source SDDC/ORG Details ###
refreshtoken = 'VCmNfciwJ2E307dGGZPNwvoLV2jwJfDB1My51SDWuKSkRnCBSuY6JVVW'
orgid = 'e74b1b6c-bccc-8857-5b58fa5c481e'
#sddcid = '28adfcaf-f2-a649-43e57593eef4' 
sddcid = '42db0333-ed8c-7e39d20ec341' 

print("Please hit Enter to accept the defaults.")

refreshtoken = input("Enter the Refresh Token ["+refreshtoken+"]:") or refreshtoken
orgid = input("Enter the Org Id ["+orgid+"]:") or orgid
sddcid = input("Enter the SDDC Id ["+sddcid+"]:") or sddcid

### Access Token ###
authurl = 'https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize?refresh_token=%s' % (refreshtoken)
headers = {'Accept': 'application/json'}
payload = {}
authresp = requests.post(authurl,headers=headers,data=payload)
authjson = json.loads(authresp.text)
token = authjson["access_token"]
headers = {'csp-auth-token': token, 'content-type': 'application/json'}
infourl = 'https://vmc.vmware.com/vmc/api/orgs/%s/sddcs/%s' %(orgid,sddcid)
	
### Get ReverseProxy URL ###
payload = {}
sddcresp = requests.get(infourl,headers=headers,data=payload)
sddcjson = json.loads(sddcresp.text)
#print("sddcresp.text")
srevproxyurl = sddcjson["resource_config"]["nsx_api_public_endpoint_url"]
vcurl = sddcjson["resource_config"]["vc_url"]
vcfqdn = vcurl.split("https://")[1].split("/")[0]
vcuser = sddcjson["resource_config"]["cloud_username"]
vcpasswd = sddcjson["resource_config"]["cloud_password"]
vcauthurl = '%srest/com/vmware/cis/session' %(vcurl)

vcvmurl = '%sapi/vcenter/vm' %(vcurl)


### DHCP Config URL's ###

dhcpsrvconfigurl = '%s/orgs/%s/sddcs/%s/sks-nsxt-manager/policy/api/v1/infra/dhcp-server-configs' %(srevproxyurl,orgid,sddcid)
dhcpsrvstatsurl = '%s/orgs/%s/sddcs/%s/sks-nsxt-manager/policy/api/v1/infra/dhcp-server-configs' %(srevproxyurl,orgid,sddcid)
dhcpleaseinfosurl = '%s/orgs/%s/sddcs/%s/sks-nsxt-manager/policy/api/v1/infra/dhcp-server-configs' %(srevproxyurl,orgid,sddcid)


#scgwurl = '%s/orgs/%s/sddcs/%s/sks-nsxt-manager/policy/api/v1/infra/domains/cgw/gateway-policies/default/rules' %(srevproxyurl,orgid,sddcid)
#smgwurl = '%s/orgs/%s/sddcs/%s/sks-nsxt-manager/policy/api/v1/infra/domains/mgw/gateway-policies/default/rules' %(srevproxyurl,orgid,sddcid)
#scgwgroupsurl = '%s/orgs/%s/sddcs/%s/sks-nsxt-manager/policy/api/v1/infra/domains/cgw/groups' %(srevproxyurl,orgid,sddcid)
#smgwupdurl = '%s/orgs/%s/sddcs/%s/sks-nsxt-manager/policy/api/v1/infra/domains/mgw/gateway-policies/default/rules' %(srevproxyurl,orgid,sddcid)
#scgwupdurl = '%s/orgs/%s/sddcs/%s/sks-nsxt-manager/policy/api/v1/infra/domains/cgw/gateway-policies/default/rules' %(srevproxyurl,orgid,sddcid)

cgwsegmenturl ='%s/orgs/%s/sddcs/%s/sks-nsxt-manager/policy/api/v1/infra/tier-1s/cgw/segments' %(srevproxyurl,orgid,sddcid)
headers = {'csp-auth-token': token, 'content-type': 'application/json'}

  
### Get all the CGW Segments ###  
payload = {}

getcgwsegresp = requests.get(cgwsegmenturl,headers=headers,data=payload)
#print(getcgwsegresp.text)

### Get DHCP Server Configs ###

payload = {}
dhcpconfigresp = requests.get(dhcpsrvconfigurl,headers=headers,data=payload)
dc = json.loads(dhcpconfigresp.text)
#print(dhcpconfigresp.text)
dhcpconfigs = dc["results"]

### Get DHCP Server Stats ###

### Get vCenter Access Key ###
authresp = requests.post(vcauthurl, auth=HTTPBasicAuth(vcuser, vcpasswd))
authjson = json.loads(authresp.text)
vcaccesskey = authjson["value"]
vcheader = {'vmware-api-session-id': vcaccesskey, 'content-type': 'application/json'}

#### Get VM Name from vCenter ###
payload = {}
vcvmsresp = requests.get(vcvmurl,headers=vcheader,data=payload)
vms = json.loads(vcvmsresp.text)
#print ("VMs from vCenter: " + vcvmsresp.text)
vmnameipmac = {}
vmmacdata = []
vmnameipmac["name"] = ''
vmnameipmac["mac"] = ''

for vm in vms:
    vmname = vm["name"]
    vmid = vm["vm"]
    vmdetailsurl = vcvmurl + "/"+vmid
    vcvmdetailsresp = requests.get(vmdetailsurl,headers=vcheader,data=payload)
    vmdetails = json.loads(vcvmdetailsresp.text)
    vmnameipmac = {}
    vmnameipmac["name"] = vm["name"]
    vmnameipmac["mac"] = vmdetails["nics"]["4000"]["mac_address"]
    #print(vmnameipmac)
    vmmacdata.append(vmnameipmac)
    #print(vmmacdata)
    #vmnameipmac["name"] = ''
    #vmnameipmac["mac"] = ''
vmipmacdata = json.dumps(vmmacdata)
#print("data:    .........."+vmipmacdata)
vmipmacdata = json.loads(vmipmacdata)
payload = {}
print("         =================DHCP Lease Records=====================          \n")
for dhcpconfig in dhcpconfigs:
    instdhcpsrvstatsurl = dhcpsrvstatsurl + "/" + dhcpconfig["id"]+ "/stats?connectivity_path=" + "/infra/tier-1s/cgw"
    dhcpconfigstatresp = requests.get(instdhcpsrvstatsurl,headers=headers,data=payload)
    ds = json.loads(dhcpconfigstatresp.text)
    ippoolstats = ds["ip_pool_stats"]
    for ippoolstat in ippoolstats:
        ippoolid = ippoolstat["dhcp_ip_pool_id"]
        instdhcpleaseinfourl = dhcpleaseinfosurl + "/" + dhcpconfig["id"]+ "/leases?connectivity_path=" + "/infra/tier-1s/cgw" + "&segment_path=" +  ippoolid
        dhcpcleaseresp = requests.get(instdhcpleaseinfourl,headers=headers,data=payload)
        dl = json.loads(dhcpcleaseresp.text)
        if "leases" in dl:
            leaserecs = dl["leases"]
            #print(dhcpcleaseresp.text)
            #### Get VM Nmae and IP Addresses ####
            for leaserec in leaserecs:
                ipaddr = leaserec["ip_address"]
                macaddr = leaserec["mac_address"]
                start_time = leaserec["start_time"]
                expire_time = leaserec["expire_time"]
                vm_name = ''
                for data in vmipmacdata:
                    #print("Mac Address from vCenrer: "+vmmac+" VM Name from vCenter: "+vmname)
                    if data["mac"] == macaddr:
                        vm_name = data["name"]

                print("DHCP Server                               IP Address                   MAC Address                      VM Name")
                print(dl["dhcp_server_id"]+"      "+leaserec["ip_address"]+"               "+leaserec["mac_address"]+"                 "+vm_name+"\n")
        




#print(vcaccesskey)



#### Get ResourcePool ID ###
#payload = {}
#vcrespoolresp = requests.get(vcrespoolurl,headers=vcheader,data=payload)
#rpjson = json.loads(vcrespoolresp.text)
#rpid = rpjson["value"][0]["resource_pool"]

### Open vCenter ###
#webbrowser.open_new_tab(vcurl)
#print("You can now login to vCenter with these credentials: \nUsername: cloudadmin@vmc.local\nPassword: "+vcpasswd)

print("############## Finished getting DHCP Lease Information ##############")