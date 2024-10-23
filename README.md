# Meraki ACL Editor

## Overview
This web app can view and edit L3 ACL's in a Meraki Network group policy.  The primary use case for this solution is to allow security teams to modify named ACL's called through RADIUS in an 802.1x deployment without having full access to the Meraki Dashboard.  The following features are implemented:
- Select Organization, Network and Group Policy
- View ACL
- Delete, modify or insert ACE
- Delete entire Group Policy
- Create new Group Policy
- Duplicate Group Policy from another network
- Bulk copy Group Policy to all networks or to networks with a specific tag

## Requirements
Written in Python 3.10 using Flask templates.  Make sure you have the necessary libraries noted in requirements.txt.  Execute using "python3 main.py"
Also tested and works as a cloud native app on Google Cloud Platform.

NOTE: The API key user must have full access to the organization to list networks.  If you do not have proper authorization the Meraki API returns a 404 error.  If your use case requires limited access to a specific network, you'll need to modify this script appropriately.

## Screenshot
<img src='https://github.com/CiscoSE/meraki-acl/blob/main/Screen%20Shot%202020-11-19.png'>

## Author
This project was developed by:
  Dave Brown (Cisco); [davibrow@cisco.com]
  

