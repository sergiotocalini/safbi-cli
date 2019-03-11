#!/usr/bin/env python
from optparse import OptionParser
from prettytable import PrettyTable
import re
import requests
import sys


def display_output(data, **kwargs):
    kwargs.setdefault('align', [])
    kwargs.setdefault('columns', data[0].keys())
    table = PrettyTable(kwargs['columns'])
    table.align = 'c'
    for a in kwargs['align']:
        table.align[a] = kwargs['align'][a]
    for i in data:
        table.add_row([i.get(k, '') for k in kwargs.get('columns', [])])
    print(table)


def login(**kwargs):
    session = requests.post(
        "http://10.100.33.11:7007/safbi/login",
        data={"email": "sergiotocalini@gmail.com", "password": "12345"}
    )
    return session


def monitoring_inventory_connections(**kwargs):
    kwargs['filter'] = dict((f.split(':')) for f in kwargs.get('filter', []))
    session = login()
    inventory = requests.get(
        "http://10.100.33.11:7007/safbi/api/monitoring/inventory",
        cookies=session.cookies
    ).json()
    data = []
    iface_types = {'1': 'Agent', '2': 'SNMP', '3': 'IPMI', '4': 'JMX'}
    iface_avail = {
        '1': 'available', '2': 'snmp_available',
        '3': 'ipmi_available', '4': 'jmx_available'
    }
    for host in inventory['data']:
        for iface in host['ifaces']:
            avail = host.get(iface_avail.get(iface['type'], 'available'), '0')
            row = {
                "hostid": host['hostid'],
                "host": host['host'],
                "status": host['status'],
                "ifaceid": iface['interfaceid'],
                "ip": iface['ip'],
                "dns": iface['dns'],
                "method": 'ip' if iface['useip'] == '1' else 'dns',
                "conn": iface['ip'] if iface['useip'] == '1' else iface['dns'],
                "type": iface_types.get(iface['type'], 'unknown'),
                "port": iface['port'],
                "main": 'yes' if iface['main'] == '1' else 'no',
                "bulk": 'yes' if iface['bulk'] == '1' else 'no',
                "available": avail,
            }
            host['match'] = True
            for f in kwargs['filter']:
                regex = re.compile(kwargs['filter'][f], re.IGNORECASE)
                if f in row and not regex.match(row[f]):
                    host['match'] = False

            if host['match']:
                data.append(row)
    return data


def main():
    parser = OptionParser(usage="usage: %prog [action] [options]",
                          version="%prog 0.0.1")
    parser.add_option("--config", dest="config",
                      default="~/.safbi/cli.yml",
                      help="Configuration file.")
    parser.add_option("--safbi-url", dest="safbi-url",
                      default=None,
                      help="SafBI URL.")
    parser.add_option("-c", "--columns", dest="columns",
                      default="nodeid,hostid,host,ifaceid,conn,port,main,type",
                      help="Display fields (ip, name, type).",
                      metavar="list")
    parser.add_option("-o", "--output", dest="output", default=None,
                      help="Output format:filename (default=stdout).",
                      type="string")
    parser.add_option("-f", "--filter", dest="filter", default=[],
                      action="append",
                      help="List of regular expression to filter results",
                      type="string")
    parser.add_option("-u", "--update", dest="update", default=[],
                      action="append",
                      help="List of fields to update",
                      type="string")

    # parser.add_option("--sortby", dest="sortby", default=[], action="append",
    #                   help="Sort the table by column", type="string")

    (opts, args) = parser.parse_args()
    options = {
        'columns': [c.lower() for c in opts.columns.split(",")],
        'filter': opts.filter,
        'update': opts.update
    }
    if args[0] == 'monitoring':
        if args[1] == 'inventory':
            if args[2] == 'connections':
                options['align'] = {
                    'host': 'r', 'ip': 'l', 'dns': 'r'
                }
                data = monitoring_inventory_connections(**options)
                display_output(data, **options)
                print('Hosts: %s' % (len(set([h['host'] for h in data]))))
                print('Connections: %s' % (len(data)))
    else:
        print("Required arguments missing or invalid.")
        print(parser.print_help())
        sys.exit(-1)


if __name__ == '__main__':
    main()
