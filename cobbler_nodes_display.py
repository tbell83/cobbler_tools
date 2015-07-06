#!/usr/bin/env python

import xmlrpclib
from prettytable import PrettyTable
import optparse
import sys

parser = optparse.OptionParser()
parser.add_option('-s', '--sort', dest='sort')
parser.add_option('-H', '--host-cobbler', dest='cobbler')
(opts, args) = parser.parse_args()

if opts.sort and opts.sort in ('hostname', 'specs', 'hypervisor', 'mac'):
    sort = opts.sort
elif opts.sort and opts.sort not in ('hostname', 'specs', 'hypervisor', 'mac'):
    print "Valid sort options are hostname, specs, hypervisor, mac"
    sys.exit(1)
else:
    sort = False

if opts.cobbler:
    cobbler_hostname = opts.cobbler
else:
    print "Please provide a target Cobbler server."
    sys.exit(1)

cobbler_user = 'api'
cobbler_password = 'password'

try:
    cobserver = xmlrpclib.Server('http://{0}/cobbler_api'
                                 .format(cobbler_hostname))
except:
    print ('Unable to reach Cobbler server! Bailing.')
    sys.exit(1)

token = cobserver.login(cobbler_user, cobbler_password)

try:
    data = cobserver.get_systems(token)
except:
    print ('Retrieval failed!')
    sys.exit(1)

nodes = []

for item in data:
    node = {}
    node['hostname'] = item['hostname']
    node['hypervisor'] = item['comment']
    node['specs'] = item['profile']
    interface = item['interfaces']
    for thing in interface:
        node['Interface'] = thing
        node['mac'] = interface[thing]['mac_address']
    nodes.append(node)

if sort and sort in ('hypervisor'):
    nodes.sort(key=lambda k: (k['hypervisor'],
                              k['hostname']))
elif sort:
    nodes.sort(key=lambda k: k[sort])

table = PrettyTable(["Hostname", "Specs", "Hypervisor", "MAC Address"])
table.align["Hostname"] = "l"
table.padding_width = 2

for node in nodes:
    table.add_row([node['hostname'], node['specs'], node['hypervisor'],
                  node['mac']])

print table
sys.exit(0)
