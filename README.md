# Meraki ACL Editor

## Overview
This web app can view, edit, create and copy L3 ACL's in a Meraki Network Group Policy.

Use cases:
- Allow security teams to modify named ACL's called through RADIUS in an 802.1x deployment without having to access the Meraki Dashboard.
- Replicate Group Policy from one network to all others or to networks with a specific tag to keep them syncronized

The following features are implemented:
- Select Organization, Network and Group Policy
- View ACL
- Delete, modify or insert ACE
- Delete entire Group Policy
- Create new Group Policy
- Duplicate Group Policy from another network
- Bulk copy Group Policy to all networks or to networks with a specific tag
## Requirements
Written in Python 3.10 using Flask templates.  Make sure you have the necessary libraries noted in requirements.txt.  Execute using "python3 main.py"
Also tested and works as a cloud native app on Google Cloud Platform AppEngine.

NOTE: The API key user must have full access to the organization to list networks.  If you do not have proper authorization the Meraki API returns a 404 error.  If your use case requires limited access to a specific network, you'll need to modify this script appropriately.

## Screenshot
<img src='https://github.com/CiscoSE/meraki-acl/blob/main/Screenshot.png'>

## Installation

Clone repository
> git clone https://github.com/CiscoSE/meraki-acl/

Create virtual environment.  Install requirements.
> cd meraki-acl \
> python3 -m venv venv \
> source venv/bin/activate \
> pip install -r requirements.txt

For testing purposes, the web app can be run directly.
For production use, recommend installing on a production web server (Apache, gunicorn, GCP, etc.).
> python3 main.py

Testing webserver will be running at http://localhost:8080

## Author
This project was developed by:
  Dave Brown (Cisco); [davibrow@cisco.com]
  

