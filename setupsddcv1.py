### Package Imports ####
import requests
import json
import time
from requests.auth import HTTPBasicAuth
import webbrowser

### Source SDDC/ORG Details ###
refreshtoken = 'DNZBo0TcQHMX8U6QnDxdS82s0B6OZSn6VWgvu5C1WILbhj'
orgid = 'e74b1b6c-bccc-4367-8857-5b55c481e'
awssubnetid = 'subnet-0011398a617514'
sddcname = 'ShashiAuto-SDDC'
awsacctid = '124030147'
mgmtsubnet = '10.148.96.0/20'
sddcsize = 'medium'
sddcregion = 'US_WEST_2'
#sddcid = '8c0d971a-4874-853d-daa532d01f39'

print("Please hit Enter to accept the defaults.")

refreshtoken = input("Enter the Refresh Token ["+refreshtoken+"]:") or refreshtoken
orgid = input("Enter the Org Id ["+orgid+"]:") or orgid
awssubnetid = input("Enter the AWS Subnet Id ["+awssubnetid+"]:") or awssubnetid
sddcname = input("Enter the SDDC Name ["+sddcname+"]:") or sddcname
awsacctid = input("Enter the AWS Account ID ["+awsacctid+"]:") or awsacctid
mgmtsubnet = input("Enter the Management Subnet CIDR ["+mgmtsubnet+"]:") or mgmtsubnet
sddcsize = input("Enter the SDDC Size ["+sddcsize+"]:") or sddcsize
sddcregion = input("Enter the SDDC Region ["+sddcregion+"]:") or sddcregion
#sddcid = input("Enter the SDDC Id ["+sddcid+"]:") or sddcid

### Access Token ###
authurl = 'https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize?refresh_token=%s' % (refreshtoken)
headers = {'Accept': 'application/json'}
payload = {}
authresp = requests.post(authurl,headers=headers,data=payload)
authjson = json.loads(authresp.text)
token = authjson["access_token"]
createsddcurl = 'https://vmc.vmware.com/vmc/api/orgs/%s/sddcs' %(orgid)
headers = {'csp-auth-token': token, 'content-type': 'application/json'}
connaccturl = 'https://vmc.vmware.com/vmc/api/orgs/%s/account-link/connected-accounts' %(orgid)

### Get AWS Account system ID ###

acctresp = requests.get(connaccturl,headers=headers,data=payload)
acctjson = json.loads(acctresp.text)
for acct in acctjson:
	if acct['account_number'] == awsacctid:
		awsacctsysid = acct['id']

### Create SDDC #

payload = {"account_link_config": {"delay_account_link": False},
    "account_link_sddc_config": [ {
        "connected_account_id": awsacctsysid,
        "customer_subnet_ids": [ awssubnetid ]
    } ],
    "deployment_type": "SingleAZ",
    "host_instance_type": "i3.metal",
    "name": sddcname,
    "num_hosts": 1,
    "provider": "AWS",
    "region": sddcregion,
    "size": sddcsize,
    "skip_creating_vxlan": True,
    "sso_domain": "vmc.local",
    "storage_capacity": 0,
    "vpc_cidr": mgmtsubnet,
    "vxlan_subnet": "192.168.1.0/24"
}
json_data = json.dumps(payload)
createsddcresp = requests.post(createsddcurl,headers=headers,data=json_data)
print(createsddcresp.text)
createdsddcjson = json.loads(createsddcresp.text)
sddcid = createdsddcjson["resource_id"]
taskid = createdsddcjson["id"]
sddc_state = "DEPLOYING"
infourl = 'https://vmc.vmware.com/vmc/api/orgs/%s/sddcs/%s' %(orgid,sddcid)
taskurl = 'https://vmc.vmware.com/vmc/api/orgs/%s/tasks/%s' %(orgid,taskid)
print(sddc_state)
payload = {}

while sddc_state == "DEPLOYING":
	ts = time.time()
	#print("Time: "+str(ts))
	#print(infourl)
	#print(sddcid)
	#print(orgid)
	taskresp = requests.get(taskurl,headers=headers,data=payload)
	taskjson = json.loads(taskresp.text)
	#print(taskresp.text)
	if "error" in taskjson and taskjson["error"] and taskjson["error"]== "Unauthorized" :
		headers = {'Accept': 'application/json'}
		payload = {}
		print("Error Unauthorized in calling task api... Renewing Access Token....")
		authresp = requests.post(authurl,headers=headers,data=payload)
		authjson = json.loads(authresp.text)
		token = authjson["access_token"]
		headers = {'csp-auth-token': token, 'content-type': 'application/json'}
	if "progress_percent" in taskjson and taskjson["progress_percent"]:
		time_left = taskjson["progress_percent"]
    
	if "status" in taskjson and taskjson["status"]:
		task_status = taskjson["status"]
    
	if "sub_status" in taskjson and taskjson["sub_status"]:
		task_substatus = taskjson["sub_status"]
    
	sddcresp = requests.get(infourl,headers=headers,data=payload)
	sddcjson = json.loads(sddcresp.text)
	#print(sddcresp.text)
    
	if "error" in sddcjson and sddcjson["error"] and sddcjson["error"]== "Unauthorized" :
		headers = {'Accept': 'application/json'}
		payload = {}
		print("Error Unauthorized in calling SDDC api...Renewing Access Token....")
		authresp = requests.post(authurl,headers=headers,data=payload)
		authjson = json.loads(authresp.text)
		token = authjson["access_token"]
		headers = {'csp-auth-token': token, 'content-type': 'application/json'}
		
	if "sddc_state" in sddcjson and sddcjson["sddc_state"]:
		sddc_state = sddcjson["sddc_state"]
		#print(sddc_state)
	if "org_id" in sddcjson and sddcjson["org_id"]:
		orgid = sddcjson["org_id"]
	if "id" in sddcjson and sddcjson["id"]:
		sddcid = sddcjson["id"]
	if time_left and task_status and task_substatus and sddc_state and isinstance(task_status,str):
		print("Percentage Complete: "+str(time_left)+"% Task Status: "+task_status+" Task Sub Status: "+task_substatus)
		print("SDDC State: "+sddc_state)
	time.sleep(300)
	payload = {}
	
### Get ReverseProxy URL ###
payload = {}
sddcresp = requests.get(infourl,headers=headers,data=payload)
sddcjson = json.loads(sddcresp.text)
srevproxyurl = sddcjson["resource_config"]["nsx_api_public_endpoint_url"]
vcurl = sddcjson["resource_config"]["vc_url"]
vcfqdn = vcurl.split("https://")[1].split("/")[0]
vcuser = sddcjson["resource_config"]["cloud_username"]
vcpasswd = sddcjson["resource_config"]["cloud_password"]
vcauthurl = '%srest/com/vmware/cis/session' %(vcurl)
vccreateliburl = '%srest/com/vmware/content/subscribed-library' %(vcurl)
s3contliburl = "http://shashitestvmc1.s3-us-west-2.amazonaws.com/lib.json"
contentlibname = "autoSetup"
deployvmurl = '%srest/com/vmware/vcenter/ovf/library-item/id:' %(vcurl)
vcdatastoreurl = '%srest/vcenter/datastore?filter.names=WorkloadDatastore' %(vcurl)
vcnetworkurl = '%srest/vcenter/network?filter.names=test-segment' %(vcurl)
vcfolderurl = '%srest/vcenter/folder?filter.names=Workloads' %(vcurl)
vcrespoolurl = '%srest/vcenter/resource-pool?filter.names=Compute-ResourcePool' %(vcurl)
vclibitemurl = '%srest/com/vmware/content/library/item?library_id=' %(vcurl)
vcpoweronvmurl = '%srest/vcenter/vm' %(vcurl)
vcconitemurl = '%srest/com/vmware/content/library/item/id:' %(vcurl)


### Source SDDC URL's ###


scgwurl = '%s/orgs/%s/sddcs/%s/sks-nsxt-manager/policy/api/v1/infra/domains/cgw/gateway-policies/default/rules' %(srevproxyurl,orgid,sddcid)

smgwurl = '%s/orgs/%s/sddcs/%s/sks-nsxt-manager/policy/api/v1/infra/domains/mgw/gateway-policies/default/rules' %(srevproxyurl,orgid,sddcid)

scgwgroupsurl = '%s/orgs/%s/sddcs/%s/sks-nsxt-manager/policy/api/v1/infra/domains/cgw/groups' %(srevproxyurl,orgid,sddcid)

smgwupdurl = '%s/orgs/%s/sddcs/%s/sks-nsxt-manager/policy/api/v1/infra/domains/mgw/gateway-policies/default/rules' %(srevproxyurl,orgid,sddcid)

scgwupdurl = '%s/orgs/%s/sddcs/%s/sks-nsxt-manager/policy/api/v1/infra/domains/cgw/gateway-policies/default/rules' %(srevproxyurl,orgid,sddcid)

testsegurl ='%s/orgs/%s/sddcs/%s/sks-nsxt-manager/policy/api/v1/infra/tier-1s/cgw/segments' %(srevproxyurl,orgid,sddcid)

headers = {'csp-auth-token': token, 'content-type': 'application/json'}

  
### Create MGW FW Rules ###
payload = {}
payload["id"]="VCInbound"
payload["description"] = "Allow vCenter Access from anywhere"
payload["source_groups"] = ["ANY"]
payload["resource_type"]= "Rule"
payload["display_name"]= "vCenter Inbound Rule"
payload["scope"]=  [ "/infra/labels/mgw" ]
payload["action"]= "ALLOW"
payload["services"]= [ "/infra/services/ICMP-ALL", "/infra/services/SSO", "/infra/services/HTTPS" ]
payload["destination_groups"]= [ "/infra/domains/mgw/groups/VCENTER"]
mgwfwurl= '%s/%s' %(smgwupdurl,"VCInbound")
json_data = json.dumps(payload)
createfwruleresp = requests.put(mgwfwurl,headers=headers,data=json_data)
print(createfwruleresp.text)
  
### Create A Test Segment ###  
payload = {}
payload["type"] = "ROUTED"
payload["id"] = "testseg"
payload["display_name"] = "test-segment"
payload["resource_type"] = "Segment"
payload["connectivity_path"] = "/infra/tier-1s/cgw"
payload["domain_name"] = "corp.local"
payload["subnets"] = [{"gateway_address": "10.141.1.1/24","dhcp_ranges": ["10.141.1.2-10.141.1.252"],"network": "10.141.1.0/24"}]

cgwsegurl= '%s/%s' %(testsegurl,"testseg")
json_data = json.dumps(payload)
createtestsegresp = requests.put(cgwsegurl,headers=headers,data=json_data)
print(createtestsegresp.text)

### Create a CGW Group for the workload Test Segment created above ###

payload = {}
payload["id"]= "testSegmentGroup"
payload["resource_type"]= "Group"
payload["display_name"]= "testSegmentGroup"
payload["expression"]= [{"ip_addresses": ["10.141.1.0/24"],"resource_type": "IPAddressExpression"}]
cgwgroupsurl= '%s/%s' %(scgwgroupsurl,"testSegmentGroup")
json_data = json.dumps(payload)
creategrpresp = requests.put(cgwgroupsurl,headers=headers,data=json_data)
print(creategrpresp.text)

### Create a CGW Rule to allow access to the Test segment created ###

payload = {}
payload["id"]= "testSegmentRule"
payload["description"] = "Allow Access to the Test Segment"
payload["source_groups"] = ["ANY"]
payload["resource_type"]= "Rule"
payload["display_name"]= "testSegmentRule"
payload["scope"]= ["/infra/labels/cgw-all"]
payload["action"]= "ALLOW"
payload["services"]= ["ANY"]
payload["destination_groups"]= ["/infra/domains/cgw/groups/testSegmentGroup"]
cgwfwurl= '%s/%s' %(scgwupdurl,"testSegmentRule")
json_data = json.dumps(payload)
createfwruleresp = requests.put(cgwfwurl,headers=headers,data=json_data)
print(createfwruleresp.text)

### Allow Internet Access to the Segment ###

payload = {}
payload["id"]= "testSegmentInternet"
payload["description"] = "Allow Access to Internet to Test Segment"
payload["source_groups"] = ["/infra/domains/cgw/groups/testSegmentGroup"]
payload["resource_type"]= "Rule"
payload["display_name"]= "testSegmentInternet"
payload["scope"]= ["/infra/labels/cgw-all"]
payload["action"]= "ALLOW"
payload["services"]= ["ANY"]
payload["destination_groups"]= ["ANY"]
cgwfwurl= '%s/%s' %(scgwupdurl,"testSegmentInternet")
json_data = json.dumps(payload)
createfwruleresp = requests.put(cgwfwurl,headers=headers,data=json_data)
print(createfwruleresp.text)

### Setup vCenter Content Library ###
authresp = requests.post(vcauthurl, auth=HTTPBasicAuth(vcuser, vcpasswd))
authjson = json.loads(authresp.text)
vcaccesskey = authjson["value"]

#print(vcaccesskey)

vcheader = {'vmware-api-session-id': vcaccesskey, 'content-type': 'application/json'}

#### Get Datastore ID ###
payload = {}
vcdatastoreresp = requests.get(vcdatastoreurl,headers=vcheader,data=payload)
dsjson = json.loads(vcdatastoreresp.text)
dsid = dsjson["value"][0]["datastore"]

#### Get Folder ID ###
payload = {}
vcfolderresp = requests.get(vcfolderurl,headers=vcheader,data=payload)
fldjson = json.loads(vcfolderresp.text)
fldid = fldjson["value"][0]["folder"]

#### Get ResourcePool ID ###
payload = {}
vcrespoolresp = requests.get(vcrespoolurl,headers=vcheader,data=payload)
rpjson = json.loads(vcrespoolresp.text)
rpid = rpjson["value"][0]["resource_pool"]

### Open vCenter ###
webbrowser.open_new_tab(vcurl)
print("You can now login to vCenter with these credentials: \nUsername: cloudadmin@vmc.local\nPassword: "+vcpasswd)

### Create Subscribed Content Library ###
payload = {"create_spec": {"description": "","type": "SUBSCRIBED", "storage_backings": [
            {
                "datastore_id": dsid,
                "type": "DATASTORE"
            }
        ],
        "subscription_info": {
            "authentication_method": "NONE",
            "automatic_sync_enabled": True,
            "subscription_url": s3contliburl,
            "on_demand": False
        },
        "name": contentlibname,
		"id": contentlibname
         }}
payload = json.dumps(payload)
contlibresp = requests.post(vccreateliburl,headers=vcheader,data=payload)
vccontlibjson = json.loads(contlibresp.text)
#print(vccontlibjson)
contlibid = vccontlibjson["value"]
#print(contlibid)
print("Content Library Created")
print("Synching the content Library in vCenter...")

time.sleep(760)

#### Get Network ID ###
payload = {}
vcnetworkresp = requests.get(vcnetworkurl,headers=vcheader,data=payload)
nwjson = json.loads(vcnetworkresp.text)
nwid = nwjson["value"][0]["network"]

#### Get Lib Item IDs from Content Lib ###
payload = {}
vclibitemurl = '%s%s' %(vclibitemurl,contlibid)
vclibitemresp = requests.get(vclibitemurl,headers=vcheader,data=payload)
lijson = json.loads(vclibitemresp.text)
libitemid = lijson["value"]
print("Library Items: "+vclibitemresp.text)

### Loop through Library Items to Deploy a Windows and a CentOS7 VM ###
for itemid in libitemid:
	payload = {}
	vcconitemurlnew = ""
	vcconitemurlnew = '%s%s' %(vcconitemurl,itemid)
	vccontitemresp = requests.get(vcconitemurlnew,headers=vcheader,data=payload)
	itemjson = json.loads(vccontitemresp.text)
	print("Library Itemp response: "+vccontitemresp.text)
	if itemjson["value"]["name"] == "CentOS7":
			vmname = "CentOS7"
			print("Deploying a CentOS VM in vCenter...")
			payload = {"deployment_spec": {
			"accept_all_EULA": True,
			"default_datastore_id": dsid,
			"network_mappings": [{
				"key": "VLAN1050",
				"value": nwid}],
				"name": vmname},
			"target": {"folder_id": fldid,
			"resource_pool_id": rpid
			}}		
	if itemjson["value"]["name"] == "win2016-template":
			vmname = "Win2016VM1"
			print("Deploying a Windows VM in vCenter...")
			payload = {"deployment_spec": {
			"accept_all_EULA": True,
			"default_datastore_id": dsid,
			"network_mappings": [{
				"key": "blackhole",
				"value": nwid}],
				"name": vmname},
			"target": {"folder_id": fldid,
			"resource_pool_id": rpid
			}}

	payload = json.dumps(payload)
	deployvmurlnew = ""
	deployvmurlnew = '%s%s?~action=deploy' %(deployvmurl,itemid)
	deployvmresp = requests.post(deployvmurlnew,headers=vcheader,data=payload)
	deployvmjson = json.loads(deployvmresp.text)
	#print(deployvmjson)
	vmid = deployvmjson["value"]["resource_id"]["id"]
	print("Created VM Name: "+vmname)
	print("Created VM ID: "+vmid)
	### Power On the VM ###
	payload = {}
	print("Powering ON the VM....")
	vcpoweronvmurlnew = ""
	vcpoweronvmurlnew = '%s/%s/power/start' %(vcpoweronvmurl,vmid)
	requests.post(vcpoweronvmurlnew,headers=vcheader,data=payload)


print("############## Finished setting up the SDDC ##############")
