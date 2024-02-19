import subprocess
import json
import copy
import argparse
from datetime import datetime
from urllib import request

# set query and file location
graph_query = f"az graph query --graph-query \"resources | where type == 'microsoft.network/frontdoorwebapplicationfirewallpolicies' | where properties.policySettings.mode != 'Prevention' | project name, properties.policySettings.mode, resourceGroup, subscriptionId\""
file_path = 'wafs-in-detection.json'

# Argument
parser = argparse.ArgumentParser(description='Analyses Azure WAFs and post result to #WAF-Monitoring Slack channel')
parser.add_argument('webhook', type=str, help='Slack Webhook URL')
args = parser.parse_args()

# date
current_date = datetime.now().date()
date_string = current_date.strftime("%d/%m/%Y")

def run_query(query):
    ''' Run query as subprocess & bring output into python '''
    try:
        result = subprocess.run(query, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output_json = json.loads(result.stdout)
        return output_json
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        print(f"stderr: {e.stderr}")
        return None

def update_slack(file_path, webhook):
    ''' Post results to Slack channel'''
    json_data = load_json(file_path)
    message_lines = []
    message_lines.append(f":firewall: *WAFs in detection mode 7+ days - {date_string}*")

    for waf in json_data:
        if waf.get('days_in_detection') >= 7:
            # get friendly name of subscription
            subscription_name = run_query(f"az account show --subscription \"{waf.get('subscriptionId')}\" --query 'name'")

            # Format message
            message_lines.append(f"> :red_circle: *{waf.get('name')}: {waf.get('days_in_detection')} days.* ({waf.get('resourceGroup')} - {subscription_name})")
    
    if  len(message_lines) <= 1:
            message_lines.append(f"> :green_circle: No WAFs in detection mode exceeding 7 day threshold")

    message = '\n'.join(message_lines)
    data = json.dumps({'text': message}).encode('utf-8')
    req = request.Request(webhook, data=data, headers={'Content-Type': 'application/json'})
    response = request.urlopen(req)
    
    # Check if message was successfully posted
    if response.status == 200:
        print(f"Message posted successfully to Slack channel.")
    else:
        print(f"Failed to post message to Slack channel. Status code: {response.status_code}")

def load_json(file_path):
    ''' Load JSON file and handle errors '''
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            print(f"JSON file '{file_path}' loaded successfully.")
        return data
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON in file '{file_path}': {e}")
        return None
    except Exception as e:
        print(f"Error loading JSON file '{file_path}': {e}")
        return None

def save_json(json_data, file_path):
    ''' Save JSON file and handle errors '''
    try:
        with open(file_path, 'w') as file:
            json.dump(json_data, file, indent=4)
            file.close()
        print(f"JSON data saved to '{file_path}' successfully.")
    except Exception as e:
        print(f"Error saving JSON data to '{file_path}': {e}")

def load_or_save_json(file_path, data_input):
    ''' Wrapper to load JSON file or initialise new JSON file for if first run '''
    # Try exisitng JSON file
    json_data = load_json(file_path)
    # File doesn't exist, initialise new file
    if json_data is None:
        print('Creating new JSON file')
        for waf in data_input:
            waf['days_in_detection'] = 0
        save_json(data_input, file_path)
        # Load 
        json_data = load_json(file_path)
    return json_data

def compare_and_update_json(file_data, query_data):
    ''' Compare JSON file with current query output, update day counter & remove WAFs changed to Prevention mode '''
    if not file_data or not query_data:
        print("Invalid JSON data.")
        return

    non_matching_items = []
    print("Updating JSON file with latest data")

    for waf in file_data:
        waf_copy = copy.deepcopy(waf)
        waf_copy.pop("days_in_detection", None)
        if waf_copy in query_data:
            waf["days_in_detection"] += 1
        else:
            non_matching_items.append(waf)

    for item in non_matching_items:
        file_data.remove(item)
    
    save_json(file_data, file_path)


# main 
query_output = run_query(graph_query)
query_output_copy = copy.deepcopy(query_output)
file_data = load_or_save_json(file_path, query_output_copy["data"])
compare_and_update_json(file_data, query_output["data"])
update_slack(file_path, args.webhook)