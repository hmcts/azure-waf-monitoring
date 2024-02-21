# azure-waf-monitoring

This repo is a github action scheduled daily @ 8:30am to retrieve a list of azure WAFs in detection mode and post WAFs in detection mode for 7 days + to #waf-monitoring Slack channel.

The waf-mode-anaylsis.py script generates a wafs-in-detection.json file which is used to track the WAFs detected using a graph query and creates an extra parameter called "days_in_detection.py" which acts a counter. As the github action runs on a daily basis, this counter tracks the number of days the WAF has been in detection mode since first detected.

The wafs-in-detection.json is loaded on each run of the github action, updated & commited back to the repo.