import requests
import json
from urllib.parse import *
from fido2.client import *
from fido2.server import *
import sys
import ctypes
import base64
import re
import json5
import os
from time import time

def login_personal(client_id, tenant_id, scope, redirect_uri, state=12345 ):
	CLIENT_ID=client_id
	CLIENT_SECRET=client_secret
	TENANT_ID=tenant_id
	SCOPE = scope
	AUTHORITY = f'https://login.microsoftonline.com/{TENANT_ID}'
	TOKEN_ENDPOINT = f'{AUTHORITY}/oauth2/v2.0/token'
	AUTHORIZATION_ENDPOINT = f'{AUTHORITY}/oauth2/v2.0/authorize'
	clnt="https://login.microsoft.com"
	client = WindowsClient(clnt)
	rpid=urlparse(clnt).netloc
	server = Fido2Server({"id": rpid, "name": "Microsoft"}, attestation="direct")
	uv='required'
	params = {'client_id': CLIENT_ID, 'response_type': 'code', 'scope': ' '.join(SCOPE), 'response_mode': 'query', 'redirect_uri':redirect_uri, 'state': str(state)}
	auth_url = f'{AUTHORIZATION_ENDPOINT}?{urlencode(params)}'
	headers={}
	headers['User-Agent']='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0 OS/10.0.22631'
	headers['Accept']='text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
	headers['Accept-Encoding']='gzip, deflate, br, zstd'
	s=requests.session()
	resp=s.get(auth_url, headers=headers)
	resptext=resp.text
	a1=resptext.index("<script")
	a2=resptext.index("</script>")
	resptext=resptext[a1+51:a2-7]
	respjson=json.loads(resptext)
	sft=respjson["sFT"]
	urlpostmsa=respjson["urlPostMsa"]
	urllogin=respjson["urlLogin"]
	urlresume=respjson["urlResume"]
	correlationid=respjson["correlationId"]
	sctx=respjson['sCtx']
	canary=respjson['canary']
	param2={}
	param2['allowedIdentities']='2'
	param2['canary']=sft
	param2['serverChallenge']=sft
	param2['postBackUrl']=f'https://login.microsoftonline.com/{TENANT_ID}/login'
	param2['postBackUrlAad']=f'https://login.microsoftonline.com/{TENANT_ID}/login'
	param2['postBackUrlMsa']=urlpostmsa
	param2['cancelUrl']=urllogin
	param2['resumeUrl']=urlresume
	param2['correlationId']=correlationid
	param2['credentialsJson']=''
	param2['ctx']=sctx
	param2['username']=''
	param2['loginCanary']=canary
	url2=f'https://login.microsoft.com/{TENANT_ID}/fido/get?uiflavor=Host'
	resp=s.post(url2, headers=headers, data=param2)
	resptext=resp.text
	a1=resptext.index("<script")
	a2=resptext.index("</script>")
	resptext=resptext[a1+51:a2-7]
	respjson=json.loads(resptext)
	scrossdomaincan=respjson['sCrossDomainCanary']
	sessionid=respjson['sessionId']
	canary=respjson['canary']
	sft=respjson['sFT']
	challenge=respjson['sFidoChallenge']
	nexturl=respjson['urlPostMsa']
	request_options, statetemp = server.authenticate_begin(user_verification=uv, challenge=challenge.encode())
	selection = client.get_assertion(request_options["publicKey"])
	result = selection.get_response(0)
	assertion={}
	assertion['id']=base64.urlsafe_b64encode(result.credential_id).decode().strip("=")
	assertion["clientDataJSON"]=base64.urlsafe_b64encode(result.client_data).decode().strip("=")
	assertion["authenticatorData"]=base64.urlsafe_b64encode(result.authenticator_data).decode().strip("=")
	assertion["signature"]=base64.urlsafe_b64encode(result.signature).decode().strip("=")
	assertion["userHandle"]=base64.urlsafe_b64encode(result.user_handle).decode().strip("=")
	userhandle=assertion["userHandle"]
	param3={}
	param3['type']='23'
	param3['ps']='23'
	param3['assertion']=json.dumps(assertion)
	param3['lmcCanary']=scrossdomaincan
	param3['hpgrequestid']=sessionid
	param3['ctx']=sctx
	param3['canary']=canary
	param3['flowToken']=sft
	url=nexturl  #f'https://login.microsoftonline.com/{TENANT_ID}/login'
	resp=s.post(url, headers=headers, data=param3)
	resptext=resp.text
	resptext2=resptext
	a1=resptext.index("<script")
	a2=resptext.index("</script>")
	resptext=resptext[a1+48:a2-1]
	respjson=json5.loads(resptext)
	sft=respjson['sFT']
	param4={}
	param4['ps']='23'
	param4['type']='23'
	param4['assertion']=param3['assertion']
	param4['hpgrequestid']=''
	param4['PPFT']=sft
	param4['ctx']=''
	param4['i19']=''
	url=respjson['urlPost']
	resp=s.post(url, headers=headers, data=param4)
	resptext=resp.text
	a1=resptext.index("ServerData")
	a2=resptext.index("</script>", a1)
	resptext=resptext[a1+12:a2-1]
	respjson=json5.loads(resptext)
	sft=sft=respjson['sFT']
	param5={}
	param5['PPFT']=sft
	param5['LoginOptions']='1'
	param5['type']='28'
	param5['ctx']=''
	param5['hpgrequestid']=''
	param5['canary']=''	
	resp=s.post(url, headers=headers, data=param5)
	resptext=resp.text
	html_string=resptext
	code_match = re.search(r'<input type="hidden" name="code" id="code" value="([^"]+)', html_string)
	if code_match:
		code = code_match.group(1)
	else:
		code = None
	state_match = re.search(r'<input type="hidden" name="state" id="state" value="([^"]+)', html_string)
	if state_match:
		state1 = state_match.group(1)
	else:
		state1 = None
	action_match = re.search(r'<form.*?action="(.*?)".*?>', html_string)
	if action_match:
		action_url = action_match.group(1)
	else:
		action_url = None
	param6={}
	param6['state']=state1
	param6['code']=code
	url=action_url
	resp=s.post(url, headers=headers, data=param6, allow_redirects=False)
	
	resphead=resp.headers
	if 'Location' not in resphead:
		resptext=resp.text
		a1=resptext.index("<script")
		a2=resptext.index("</script>")
		resptext=resptext[a1+51:a2-7]
		respjson=json.loads(resptext)
		msg=respjson['strServiceExceptionMessage']
		raise Exception(msg)
	loc=resphead['Location']
	a1=loc.index('?code=')
	a2=loc.index('&', a1)
	code=loc[a1+6:a2]
	a1=loc.index('state=')
	a2=loc.index('&', a1)
	state2=loc[a1+6:a2]
	st=int(state2)
	if st==state:
		return code
	else:
		raise Exception("State mismatch. Probable MITM")
	
def login_work_or_school(client_id, tenant_id, scope, redirect_uri, state=12345 ):
	CLIENT_ID=client_id
	CLIENT_SECRET=client_secret
	TENANT_ID=tenant_id
	SCOPE = scope
	AUTHORITY = f'https://login.microsoftonline.com/{TENANT_ID}'
	TOKEN_ENDPOINT = f'{AUTHORITY}/oauth2/v2.0/token'
	AUTHORIZATION_ENDPOINT = f'{AUTHORITY}/oauth2/v2.0/authorize'
	clnt="https://login.microsoft.com"
	client = WindowsClient(clnt)
	rpid=urlparse(clnt).netloc
	server = Fido2Server({"id": rpid, "name": "Microsoft"}, attestation="direct")
	uv='preferred'
	params = {'client_id': CLIENT_ID, 'response_type': 'code', 'scope': ' '.join(SCOPE), 'response_mode': 'query', 'redirect_uri':'http://localhost/myapp/', 'state': '12345'}
	auth_url = f'{AUTHORIZATION_ENDPOINT}?{urlencode(params)}'
	headers={}
	headers['User-Agent']='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0 OS/10.0.22631'
	headers['Accept']='text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
	headers['Accept-Encoding']='gzip, deflate, br, zstd'
	s=requests.session()
	resp=s.get(auth_url, headers=headers)
	resptext=resp.text
	a1=resptext.index("<script")
	a2=resptext.index("</script>")
	resptext=resptext[a1+51:a2-7]
	respjson=json.loads(resptext)
	sft=respjson["sFT"]
	urlpostmsa=respjson["urlPostMsa"]
	urllogin=respjson["urlLogin"]
	urlresume=respjson["urlResume"]
	correlationid=respjson["correlationId"]
	sctx=respjson['sCtx']
	canary=respjson['canary']
	param2={}
	param2['allowedIdentities']='2'
	param2['canary']=sft
	param2['serverChallenge']=sft
	param2['postBackUrl']=f'https://login.microsoftonline.com/{TENANT_ID}/login'
	param2['postBackUrlAad']=f'https://login.microsoftonline.com/{TENANT_ID}/login'
	param2['postBackUrlMsa']=urlpostmsa
	param2['cancelUrl']=urllogin
	param2['resumeUrl']=urlresume
	param2['correlationId']=correlationid
	param2['credentialsJson']=''
	param2['ctx']=sctx
	param2['username']=''
	param2['loginCanary']=canary
	url2=f'https://login.microsoft.com/{TENANT_ID}/fido/get?uiflavor=Host'
	resp=s.post(url2, headers=headers, data=param2)
	resptext=resp.text
	a1=resptext.index("<script")
	a2=resptext.index("</script>")
	resptext=resptext[a1+51:a2-7]
	respjson=json.loads(resptext)
	scrossdomaincan=respjson['sCrossDomainCanary']
	sessionid=respjson['sessionId']
	canary=respjson['canary']
	sft=respjson['sFT']
	challenge=respjson['sFidoChallenge']
	request_options, statefido = server.authenticate_begin(user_verification=uv, challenge=challenge.encode())
	selection = client.get_assertion(request_options["publicKey"])
	result = selection.get_response(0)
	assertion={}
	assertion['id']=base64.urlsafe_b64encode(result.credential_id).decode().strip("=")
	assertion["clientDataJSON"]=base64.urlsafe_b64encode(result.client_data).decode().strip("=")
	assertion["authenticatorData"]=base64.urlsafe_b64encode(result.authenticator_data).decode().strip("=")
	assertion["signature"]=base64.urlsafe_b64encode(result.signature).decode().strip("=")
	assertion["userHandle"]=base64.urlsafe_b64encode(result.user_handle).decode().strip("=")
	userhandle=assertion["userHandle"]
	param3={}
	param3['type']='23'
	param3['ps']='23'
	param3['assertion']=json.dumps(assertion)
	param3['lmcCanary']=scrossdomaincan
	param3['hpgrequestid']=sessionid
	param3['ctx']=sctx
	param3['canary']=canary
	param3['flowToken']=sft
	url=f'https://login.microsoftonline.com/{TENANT_ID}/login'
	resp=s.post(url, headers=headers, data=param3)
	resptext=resp.text
	resptext2=resptext
	a1=resptext.index("<script")
	a2=resptext.index("</script>")
	resptext=resptext[a1+51:a2-7]
	respjson=json.loads(resptext)
	sctx=respjson['sCtx']
	sessionid=respjson['sessionId']
	sft=respjson['sFT']
	canary=respjson['canary']
	url='https://login.microsoftonline.com/kmsi'
	param4={}
	param4['LoginOptions']='1'
	param4['type']='28'
	param4['ctx']=sctx
	param4['hpgrequestid']=sessionid
	param4['flowToken']=sft
	param4['canary']=canary
	param4['i19']='4086'
	resp=s.post(url, headers=headers, data=param4, allow_redirects=False)
	resphead=resp.headers
	if 'Location' not in resphead:
		resptext=resp.text
		a1=resptext.index("<script")
		a2=resptext.index("</script>")
		resptext=resptext[a1+51:a2-7]
		respjson=json.loads(resptext)
		msg=respjson['strServiceExceptionMessage']
		raise Exception(msg)
	loc=resphead['Location']
	a1=loc.index('?code=')
	a2=loc.index('&', a1)
	code=loc[a1+6:a2]
	a1=loc.index('state=')
	a2=loc.index('&', a1)
	state2=loc[a1+6:a2]
	st=int(state2)
	if st==state:
		return code
	else:
		raise Exception("State mismatch. Probable MITM")
	
if __name__=='__main__':	
	os.system('cls')
	print("Using custom workflow")
	print()
	starttime=time()
	scope=['User.Read']
	tenant_id = 'REDACTED' #Use yours
	client_id = 'REDACTED' #Use yours
	client_secret = 'REDACTED' #Use yours
	redirect_uri='http://localhost/myapp/'
	print("Initiating login process")
	code=login_personal(client_id, tenant_id, scope, redirect_uri)
	print("Received code. Requesting for Access token.")
	param={}
	param['client_id']=client_id
	param['scope']=''.join(scope)
	param['code']=code
	param['redirect_uri']=redirect_uri
	param['grant_type']='authorization_code'
	param['client_secret']=client_secret
	url=f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
	resp=requests.post(url, data=param)
	respjson=resp.json()
	token=respjson['access_token']
	print("Received access token.")
	print("Making Graph API call to /me.")
	graphurl= 'https://graph.microsoft.com/v1.0/me'
	headers={'Authorization': f'Bearer {token}'}
	resp=requests.get(graphurl, headers=headers)
	respjson=resp.json()
	print(json.dumps(respjson, indent=4))
	endtime=time()
	timetaken=int(endtime-starttime)
	print()
	print("Time taken: ", timetaken, " seconds")

