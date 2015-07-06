#!/usr/bin/python

from netaddr import IPNetwork, IPAddress, AddrFormatError
import re
import xmlrpclib
import logging

logging.basicConfig(filename='/var/log/cobbler/cobbler.log',
                    level=logging.DEBUG)

cobbler_hostname = 'cobbler_fqdn'
cobbler_user = 'cobbler'
cobbler_pswd = 'password'

logging.info('Cobbler Server: %s', cobbler_hostname)

try:
    cobserver = xmlrpclib.Server('http://{0}/cobbler_api'
                                 .format(cobbler_hostname))
    logging.info('Cobbler Object %s', cobserver)
except:
    logging.critical('Unable to reach Cobbler server! Bailing.')
    exit()

token = cobserver.login(cobbler_user, cobbler_pswd)
logging.info('Cobbler Token: %s', token)

logging.info('Syncing Cobbler')
try:
    cobserver.sync(token)
except:
    logging.critical('Cobbler Sync Failed! Bailing.')
    exit()
logging.info('Sync Complete')


# Derive appropriate subnet from FQDN
def get_subnet(fqdn):
    try:
        (host, subnet_input, environment, tld_input) = fqdn.split('.')
    except:
        try:
            (host, subnet_input, tld_input) = fqdn.split('.')
            environment = None
        except:
            logging.critical('Invalid FQDN! Bailing.')
            exit(1)

    if environment is None:
        logging.info('Environment not defined in FQDN. Using production.')
        subnet = {'mgt': '0.0/22',
                  'svc': '4.0/22',
                  'int': '16.0/20',
                  'lbl': '32.0/20',
                  'emp': '64.0/19'}

    elif environment == 'stg':
        subnet = {'mgt': '128.0/22',
                  'svc': '132.0/22',
                  'int': '144.0/20',
                  'lbl': '160.0/20',
                  'emp': '192.0/18'}

    elif environment == 'tst':
        subnet = {'int': '176.0/22',
                  'lbl': '180.0/22'}

    elif environment == 'prd':
        subnet = {'mgt': '0.0/22',
                  'svc': '4.0/22',
                  'int': '16.0/20',
                  'lbl': '32.0/20',
                  'emp': '64.0/19'}

    else:
        logging.critical('Bad FQDN! Bailing.')
        exit(1)

    tld = {'chf': '10.10.',
           'csh': '10.20.',
           'usv': '10.30.'}
    try:
        return IPNetwork(tld[tld_input]+subnet[subnet_input])
    except:
        if environment == 'tst' and subnet_input not in subnet:
            logging.critical('Invalid environment/subnet combination! Bailing.')
        else:
            logging.critical('Something has gone wrong! Bailing.')
        exit(1)


# Confirm IP address is in required subnet
def address_in_network(ip, network):
    return ip in network


# Get list of IPs in use by Cobbler
def get_ips_in_use():
    logging.info('Getting list of active IPs')
    ips = []
    try:
        logging.info('Pulling IP info from Cobbler')
        data = cobserver.get_systems(token)
    except:
        logging.critical('Unable to get IP info from Cobbler server! Bailing.')
        exit(1)

    for item in data:
        interface = item['interfaces']
        try:
            interface['eth0']['ip_address']
            try:
                ips.append(IPAddress(interface['eth0']['ip_address']))
            except:
                logging.critical("No IP Address for %s", item['name'])
        except:
            logging.critical("No eth0 defined for %s", item['name'])
    logging.info('IPs in use: %s', len(ips))
    return ips


# ip is not in getIPsInUse
# ip is valid IPAddress + regexp
# ip is in subnet
def is_valid_ip(ip, network, ips_in_use):
    try:
        IPAddress(ip)
    except AddrFormatError:
        return False
    if IPAddress(ip) in ips_in_use:
        return False
    if not address_in_network(IPAddress(ip), network):
        return False
    if re.match(r'10\.(10|20|30)\.[0-9]*\.(255|0|1)$', ip) is not None:
        return False
    if re.match(r'10\.(10|20|30)\.(0|4|16|32|64|96|128|132|144|160|176|180|192|224)\.([0-9]{1,2})$', ip) is not None:
        return False
    else:
        return True


# Get unused IP address
def get_unused_ip(hostname):
    logging.info('Generating unused IP address')
    subnet = IPNetwork(get_subnet(hostname))
    logging.info('Target subnet: %s', subnet)
    ip = str(subnet).split('/')
    ip = IPAddress(ip[0])
    logging.info('%s', ip)
    ips_in_use = get_ips_in_use()
    while not is_valid_ip(str(ip), subnet, ips_in_use):
        ip += 1
    logging.info('Here\'s your IP: %s', ip)
    return ip


# Get default gateway for hostname
def get_gateway(hostname):
    gateway = str(IPAddress(str(get_subnet(hostname)).split('/')[0]) + 1)
    return gateway


# Get hostnames from systems definitions in cobbler for systems with interfaces
# defined
def get_hostnames():
    logging.info('Getting list of hosts')
    hostnames = []
    data = cobserver.get_systems(token)
    for item in data:
        name = item['name']
        try:
            interface = item['interfaces']
            ip_address = interface['eth0']['ip_address']
        except:
            logging.info('No ip address configured for %s', name)
            hostnames.append(name)
    return hostnames

fqdn = get_hostnames()
hosts = {}

if len(fqdn) == 0:
    logging.info('No viable hosts, quitting')
    exit(0)
else:
    for hostname in fqdn:
        logging.info('Host: %s', hostname)
        address = get_unused_ip(hostname)
        logging.info('IP Address: %s', address)
        hosts[hostname] = str(address)

for host in hosts:
    hostname = host
    try:
        (name, subnet_name, environment, location) = hostname.split('.')
    except:
        try:
            (name, subnet_name, location) = hostname.split('.')
            environment = None
        except:
            logging.critical('Invalid FQDN! Bailing.')
            exit(1)

    if environment is None:
        subnet = subnet_name
    elif environment == 'tst':
        subnet = 'test-' + subnet_name
    elif environment == 'stg':
        subnet = 'stage-' + subnet_name
    elif environment == 'prd':
        subnet = subnet_name
    else:
        logging.critical('Something has gone wrong with the subnet! Bailing.')
        exit(1)
    ip_address = hosts[host]
    gateway = get_gateway(hostname)
    subnet_mask = str(IPNetwork(get_subnet(hostname)).netmask)
    handle = cobserver.get_system_handle(hostname, token)
    logging.info("%s - %s - %s", hostname, ip_address, handle)
    cobserver.modify_system(handle, 'hostname', host, token)
    cobserver.modify_system(handle, 'modify_interface', {
        'ipaddress-eth0': ip_address,
        'macaddress-eth0': 'random',
        'dnsname-eth0': hostname,
        'static-eth0': 'True',
        'ifgateway-eth0': gateway,
        'subnet-eth0': subnet_mask,
        'virt_bridge-eth0': subnet
        }, token)
    cobserver.modify_system(handle, 'virt_type', 'qemu', token)
    cobserver.modify_system(handle, 'virt_auto_boot', '1', token)
    cobserver.save_system(handle, token)

cobserver.sync(token)
