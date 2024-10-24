#!python3
# [START gae_python310_app]

"""
Copyright (c) 2024 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
               https://developer.cisco.com/docs/licenses
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""
__author__ = "David Brown <davibrow@cisco.com>"
__contributors__ = []
__copyright__ = "Copyright (c) 2012 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"

from flask import Flask, request, make_response, render_template, redirect, url_for, session
from markupsafe import Markup
import meraki


app = Flask(__name__)
app.secret_key = 'any random string'


###########################################################################
#  Prompt user to choose an org from a list of orgs attached to the API key
###########################################################################
@app.route('/org/')
def get_org():

    api_key = request.cookies.get('api_key')
    if api_key is None:
        return redirect(url_for('getapikey'))
    db = meraki.DashboardAPI(api_key=api_key, suppress_logging=True)
    orgs = db.organizations.getOrganizations()
    list_orgs = ''
    for org in orgs:
        list_orgs += f'<option value = "{org["id"]}">{org["name"]}</option>\n'

    return render_template('listorgs.html', listorgs=Markup(list_orgs))


###########################################################################
#  Prompt user to choose an network from a list of networks in this org
###########################################################################
@app.route('/network/')
def get_network():

    api_key = request.cookies.get('api_key')
    if api_key is None:
        return redirect(url_for('getapikey'))
    organization_id = request.args.get('org') or session['orgid']
    session['orgid'] = organization_id
    db = meraki.DashboardAPI(api_key=api_key, suppress_logging=True)
    org_name = db.organizations.getOrganization(organizationId=organization_id)['name']
    session['org'] = org_name
    networks = db.organizations.getOrganizationNetworks(organizationId=organization_id)
    list_networks = ''
    for network in networks:
        list_networks += f'<option value = "{network["id"]}">{network["name"]}</option>\n'

    return render_template('listnetworks.html', org=org_name, listnetworks=Markup(list_networks))


###########################################################################
#  Prompt user to choose an ACL from this network
###########################################################################
@app.route('/acl/')
def list_acls():

    api_key = request.cookies.get('api_key')
    if api_key is None:
        return redirect(url_for('getapikey'))
    network_id = request.args.get('network') or session['netid']
    session['netid'] = network_id
    db = meraki.DashboardAPI(api_key=api_key, suppress_logging=True)
    policies = db.networks.getNetworkGroupPolicies(networkId=network_id)
    list_policies = ''
    for policy in policies:
        list_policies += f'<option value = "{policy["groupPolicyId"]}">{policy["name"]}</option>\n'
    organization_id = request.args.get('org') or session['orgid']
    network_name = db.networks.getNetwork(networkId=network_id)['name']
    session['network'] = network_name
    networks = db.organizations.getOrganizationNetworks(organizationId=organization_id)
    list_networks = ''
    for network in networks:
        list_networks += f'<option value = "{network["id"]}">{network["name"]}</option>\n'

    session['lastaclaction'] = 'Select an action below:'

    return render_template('listpolicies.html', org=session['org'], network=network_name,
                            orgid=session['orgid'], listpolicies=Markup(list_policies),
                            listnetworks=Markup(list_networks))


###########################################################################
#  Prompt user to choose a Group Policy to duplicate from another network
###########################################################################
@app.route('/copyacl/')
def copyacl():

    api_key = request.cookies.get('api_key')
    if api_key is None:
        return redirect(url_for('getapikey'))
    db = meraki.DashboardAPI(api_key=api_key, suppress_logging=True)
    source_net = request.args.get('sourcenet')
    network_name = db.networks.getNetwork(networkId=source_net)['name']
    policies = db.networks.getNetworkGroupPolicies(networkId=source_net)
    list_policies = ''
    for policy in policies:
        list_policies += f'<option value = "{policy["groupPolicyId"]}">{policy["name"]}</option>\n'

    return render_template('copypolicy.html', network=network_name,
                            listpolicies=Markup(list_policies), sourcenet=source_net)


###########################################################################
#  Apply copied policy
###########################################################################
@app.route('/applycopy/')
def applycopy():

    api_key = request.cookies.get('api_key')
    if api_key is None:
        return redirect(url_for('getapikey'))
    network_id = session['netid']
    db = meraki.DashboardAPI(api_key=api_key, suppress_logging=True)
    source_net = request.args.get('sourcenet')
    acl = request.args.get('acl')
    acl_name = request.args.get('aclname')
    network_name = db.networks.getNetwork(networkId=source_net)['name']
    policy = db.networks.getNetworkGroupPolicy(networkId=source_net, groupPolicyId=acl)

    if acl_name in ('', None):
        acl_name = policy['name']
    try:
        new_policy = db.networks.createNetworkGroupPolicy(networkId=network_id, name=acl_name,
                                                          scheduling=policy['scheduling'],
                                                          bandwidth=policy['bandwidth'],
                                                          firewallAndTrafficShaping=policy['firewallAndTrafficShaping'],
                                                          contentFiltering=policy['contentFiltering'],
                                                          splashAuthSettings=policy['splashAuthSettings'],
                                                          vlanTagging=policy['vlanTagging'],
                                                          bonjourForwarding=policy['bonjourForwarding'])
    except Exception as e:
        return Markup(f"<h1>Error:</h1>{e}")

    session['acl'] = new_policy['groupPolicyId']
    session['lastaclaction'] = f'<p style="color:red;"><b>Copied Policy from {network_name}.</b></p>'
    resp = make_response(redirect(url_for('list_aces')))

    return resp


###########################################################################
#  Create a new Group Policy
###########################################################################
@app.route('/newpolicy/')
def newpolicy():

    policyname = request.args.get('newpolicy')
    api_key = request.cookies.get('api_key')
    if api_key is None:
        return redirect(url_for('getapikey'))
    network_id = session['netid']
    db = meraki.DashboardAPI(api_key=api_key, suppress_logging=True)

    try:
        newpolicy = db.networks.createNetworkGroupPolicy(networkId=network_id, name=policyname)
    except Exception as e:
        return Markup(f"<h1>Error:</h1>{e}")

    session['acl'] = newpolicy['groupPolicyId']
    session['lastaclaction'] = '<b>Created new policy with blank ACL.</b>'
    resp = make_response(redirect(url_for('list_aces')))

    return resp


###########################################################################
#  LIST ACL and Select ACE Action (Delete, Replace, Insert)
###########################################################################
@app.route('/ace/')
def list_aces():

    api_key = request.cookies.get('api_key')
    if api_key is None:
        return redirect(url_for('getapikey'))
    acl = request.args.get('acl') or str(session['acl'])
    session['acl'] = acl
    network_id = session['netid']
    db = meraki.DashboardAPI(api_key=api_key, suppress_logging=True)
    policy = db.networks.getNetworkGroupPolicy(networkId=network_id, groupPolicyId=acl)
    session['policyname'] = policy['name']
    acl_table = ''
    for n, ace in enumerate(policy['firewallAndTrafficShaping']['l3FirewallRules']):
        acl_table += f'<td><input type="radio" name="ace" value = "{n}"></td><th>{n+1}</th>'
        for var in ace.values():
            acl_table += f'<td>{var}</td>'
        acl_table += '</tr>\n'

    networks = db.organizations.getOrganizationNetworks(organizationId=session['orgid'])
    tags = []
    for n in networks:
        for t in n['tags']:
            tags.append(t)
    tag_list = '<option value=""></option>\n'
    for tag in set(tags):
        tag_list += f'<option value = "{tag}">{tag}</option>\n'

    return render_template('listacl.html', acl=policy['name'], lastaclaction=Markup(session['lastaclaction']),
                           acltable=Markup(acl_table), org=session['org'], network=session['network'],
                           tag_list=Markup(tag_list))


###########################################################################
#  Edit (Delete, Replace, Insert) ACL Entry
###########################################################################
@app.route('/editacl/')
def editace():

    api_key = request.cookies.get('api_key')
    if api_key is None:
        return redirect(url_for('getapikey'))
    acl = session['acl']
    ace = request.args.get('ace')
    if ace in ('', None):
        session['lastaclaction'] = '<p style="color:red;">You must select an ACL line</p>'
        resp = make_response(redirect(url_for('list_aces')))
        return resp
    network_id = session['netid']
    db = meraki.DashboardAPI(api_key=api_key, suppress_logging=True)
    policy = db.networks.getNetworkGroupPolicy(networkId=network_id, groupPolicyId=acl)
    session['policyname'] = policy['name']

    acl_action = int(request.args.get('aclaction'))
    if acl_action in (1, 2, 3):
        comment = request.args.get('comment')
        if comment is None:
            comment = ''
        dest_port = request.args.get('port')
        protocol = request.args.get('protocol')
        if dest_port in ('any', 'Any', '') or protocol == 'icmp':
            dest_port = 'Any'
        dest = request.args.get('dest')
        if dest == '':
            dest = 'Any'
        ace_line = {'comment': comment, 'policy': request.args.get('action'), 'protocol': protocol,
            'destPort': dest_port, 'destCidr': dest}

    if acl_action == 0:
        # Delete ACE #####
        if ace == 'last':
            session['lastaclaction'] = '<p style="color:red">Cannot delete implicit ALLOW ANY rule</p>'
        else:
            session['lastaclaction'] = f'Deleted line {int(ace)+1}: ' \
                                       f'{policy["firewallAndTrafficShaping"]["l3FirewallRules"].pop(int(ace))}'

    elif acl_action == 1:
        # Replace ACE #####
        if ace == 'last':
            session['lastaclaction'] = '<p style="color:red">Cannot edit implicit ALLOW ANY rule</p>'
        else:
            policy['firewallAndTrafficShaping']['l3FirewallRules'][int(ace)] = ace_line
            session['lastaclaction'] = f'Line {int(ace)+1} modified: {ace_line}'

    elif acl_action == 2:
        # Insert ACE above line #####
        if ace == 'last':
            ace = len(policy['firewallAndTrafficShaping']['l3FirewallRules'])
        policy['firewallAndTrafficShaping']['l3FirewallRules'].insert(int(ace), ace_line)
        session['lastaclaction'] = f'Inserted line {int(ace)+1}: {ace_line}'

    elif acl_action == 3:
        # Insert ACE below line #####
        if ace == 'last':
            session['lastaclaction'] = 'Cannot insert a line below the implicit ALLOW ANY rule'
        else:
            policy['firewallAndTrafficShaping']['l3FirewallRules'].insert(int(ace)+1, ace_line)
            session['lastaclaction'] = f'Inserted line {int(ace)+2}: {ace_line}'

    policy['firewallAndTrafficShaping']['settings'] = 'custom'
    policy_id = policy.pop('groupPolicyId')
    test = db.networks.updateNetworkGroupPolicy(networkId=network_id, groupPolicyId=policy_id,
                                                firewallAndTrafficShaping=policy['firewallAndTrafficShaping'])

    resp = make_response(redirect(url_for('list_aces')))

    return resp


###########################################################################
#  Confirm Policy Deletion & Perform Deletion
###########################################################################
@app.route('/deleteconfirm/')
def deleteconfirm():

    return render_template('deleteconfirm.html', policyname=session['policyname'], network = session['network'])


@app.route('/deleteacl/')
def deleteacl():

    api_key = request.cookies.get('api_key')
    if api_key is None:
        return redirect(url_for('getapikey'))
    acl = session['acl']
    network_id = session['netid']
    db = meraki.DashboardAPI(api_key=api_key, suppress_logging=True)
    db.networks.deleteNetworkGroupPolicy(networkId=network_id, groupPolicyId=acl)

    resp = make_response(redirect(url_for('list_acls')))

    return resp


###########################################################################
#  Prompt user for Meraki API key
###########################################################################
@app.route('/')
def getapikey():
    api_key = request.cookies.get('api_key')
    if api_key is None:
        api_key = 'not set'
    else:
        api_key = '**************************' + api_key[-5:]
    return render_template('setapikey.html', api_key=api_key)


###########################################################################
#  Read and set Meraki API Key
###########################################################################
@app.route('/setapikey/')
def setapikey():

    resp = make_response(redirect(url_for('get_org')))
    resp.set_cookie('api_key', request.args.get("api_key"))

    return resp


###########################################################################
#  Copies or updates policy to all networks or all networks matching tag
###########################################################################
@app.route('/bulkcopy/')
def bulk_copy():

    api_key = request.cookies.get('api_key')
    if api_key is None:
        return redirect(url_for('getapikey'))
    acl = session['acl']
    network_id = session['netid']
    db = meraki.DashboardAPI(api_key=api_key, suppress_logging=True)
    tag = request.args.get('tag')
    networks = db.organizations.getOrganizationNetworks(organizationId=session['orgid'])
    policy = db.networks.getNetworkGroupPolicy(networkId=network_id, groupPolicyId=acl)
    updated = f'<a href="/ace">Return</a><br><br>\n' \
              f'Policy updated to:<br>\n<ul>\n'
    added = f'</ul>\nPolicy added to:<br>\n<ul>\n'
    errors = f'</ul>\nErrors encountered with:<br>\n<ul>\n'

    for network in networks:
        if network['id'] == network_id:
            continue
        if (tag in network['tags']) or (tag in ('', None)):
            policies = db.networks.getNetworkGroupPolicies(networkId=network['id'])
            policy_id = None
            for target_policy in policies:
                if target_policy['name'] == policy['name']:
                    policy_id = target_policy['groupPolicyId']
                    break
            if policy_id:
                try:
                    new_policy = \
                        db.networks.updateNetworkGroupPolicy(networkId=network['id'],
                                                             groupPolicyId=policy_id,
                                                             scheduling=policy['scheduling'],
                                                             bandwidth=policy['bandwidth'],
                                                             firewallAndTrafficShaping=policy['firewallAndTrafficShaping'],
                                                             contentFiltering=policy['contentFiltering'],
                                                             splashAuthSettings=policy['splashAuthSettings'],
                                                             vlanTagging=policy['vlanTagging'],
                                                             bonjourForwarding=policy['bonjourForwarding'])
                    updated += f'<li>{network["name"]}\n'
                except Exception as e:
                    errors += f'<li>{network["name"]} - {e}'
            else:
                try:
                    new_policy =\
                        db.networks.createNetworkGroupPolicy(networkId=network['id'],
                                                             name=policy['name'],
                                                             scheduling=policy['scheduling'],
                                                             bandwidth=policy['bandwidth'],
                                                             firewallAndTrafficShaping=policy['firewallAndTrafficShaping'],
                                                             contentFiltering=policy['contentFiltering'],
                                                             splashAuthSettings=policy['splashAuthSettings'],
                                                             vlanTagging=policy['vlanTagging'],
                                                             bonjourForwarding=policy['bonjourForwarding'])
                    added += f'<li>{network["name"]}\n'
                except Exception as e:
                    errors += f'<li>{network["name"]} - {e}'
    content = f'{updated}{added}{errors}</ul>'
    return Markup(content)


if __name__ == '__main__':
    # This is used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. This
    # can be configured by adding an `entrypoint` to app.yaml.
    app.run(host='127.0.0.1', port=8080, debug=True)
# [END gae_python38_app]
