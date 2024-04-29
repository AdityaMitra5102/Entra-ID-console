from flask import Flask, request, redirect
import requests
import json
import webbrowser
from threading import Thread
import logging
import os
from time import time

app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.disabled = True
# Configuration
scope = ['User.Read']
tenant_id = 'REDACTED'
client_id = 'REDACTED'
client_secret = 'REDACTED'
redirect_uri = 'http://localhost:5000/myapp/'

# Authentication endpoints
authorize_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize'
token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'



# Routes
@app.route('/')
def index():
    os.system('cls')
    print("Using traditional workflow")
    print()
    print("Initiating login process")
    return redirect(authorize_url + '?client_id=' + client_id + '&response_type=code&redirect_uri=' + redirect_uri + '&scope=' + ' '.join(scope))

@app.route('/myapp/')
def myapp():
    global starttime
    auth_code = request.args.get('code')
    print("Received code. Requesting for Access token.")
    token_data = {
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': redirect_uri,
        'client_id': client_id,
        'client_secret': client_secret,
    }
    token_response = requests.post(token_url, data=token_data)
    token = token_response.json().get('access_token')
    print("Received access token.")
    print("Making Graph API call to /me.")
    me_response = requests.get('https://graph.microsoft.com/v1.0/me', headers={'Authorization': 'Bearer ' + token})
    res= json.dumps(me_response.json(), indent=4)
    print(res)
    currtime=time()
    timetaken=int(currtime-starttime)
    print()
    print("Time taken: ", timetaken, " seconds")
    os.system('taskkill /IM chrome.exe /F > NUL & taskkill /IM python.exe /F> NUL')
    exit()
    return res

def start_browser():
    global starttime
    starttime=time()
    chrome_path = 'C:/Program Files/Google/Chrome/Application/chrome.exe %s --incognito'
    webbrowser.get(chrome_path).open('http://localhost:5000')

if __name__ == '__main__':
    thread=Thread(target=start_browser)
    thread.start()
    app.run(host='0.0.0.0', port=5000)

