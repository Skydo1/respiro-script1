# This is a script to find the VPCs associated with the source and
# This is a script to find the VPCs associated with the source and
# destination addresses from the required source and destination
# addresses csv file


# imports

import pandas as pd
import ipaddress
import csv
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError

import socket
import whois
from openpyxl import load_workbook

#Globals
unknown_address= []

def check_tcp_known(checking_on):
    found = []
    tcp = ""
    tcp_ports = pd.read_csv('tcp.csv')
    for x in tcp_ports.index:
        if checking_on == tcp_ports['port'][x]:
            tcp = tcp_ports['description'][x]
            print(tcp)
            found.append(tcp)
    if found:
        return tcp
    else:
        return 'unkown'

def count_dest_ports(filename):
    headers = ['port number', 'hit count']
    table = {}
    table2 = {}
    with open('ports_counts.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        temp = []
        req_dest = pd.read_csv(filename)
        x = 0
       
        for x in range(0,1023):
            count = 0
            for index in req_dest.index:
                if int(req_dest['Destination Port'][index]) not in range(0, 1023):
                    continue
                if(int(req_dest['Destination Port'][index]) ==  x):
                    if req_dest['Source Address'][index] in table.get(x, []):
                        count = count + 1
                    else:
                        if x not in table:
                            table[x] =[]
                        table[x].append(req_dest['Source Address'][index])
                        count = count + 1
            if (count == 0):
                x = x + 1
                temp.clear()
            else: 
                temp.append(x)
                temp.append(count)
                print(temp)
                writer.writerow(temp)
                temp.clear()
                x = x + 1
    with open('source address to wellknow destinations.txt', 'w') as f:
        f.write('all the macthing')
        f.write('\n')
        f.write('\n')
        for x, y in table.items():
            f.write(f"{x} : {y}")
            f.write('\n')
    
    req_dest = pd.read_csv(filename)
    for index in req_dest.index:
        source_port = int(req_dest['Source Port'][index])
        source_ip = req_dest['Source Address'][index]
        if int(req_dest['Source Port'][index]) not in range(0, 1023):
            continue
        else:
            if source_ip not in table2:
                table2[source_ip] = {}
            if source_port not in table2[source_ip]:
                table2[source_ip][source_port] = []
            table2[source_ip][source_port].append(req_dest['Destination Address'][index])
    with open('target address access others.txt', 'w') as f:
        f.write('all the macthing')
        f.write('\n')
        f.write('\n')
        for ip, ports in table2.items():
            for port, addresses in ports.items():
                f.write(f"{ip}-{port}: {addresses}\n")


def count_dest_ports_target_dest(filename):
    headers = ['port number', 'hit count']
    table = {}
    table2 = {}
    with open('ports_counts(target is destination).csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        temp = []
        req_dest = pd.read_csv(filename)
        x = 0
       
        for x in range(0,1023):
            count = 0
            for index in req_dest.index:
                if int(req_dest['Destination Port'][index]) not in range(0, 1023):
                    continue
                if(int(req_dest['Destination Port'][index]) ==  x):
                    if req_dest['Source Address'][index] in table.get(x, []):
                        count = count + 1
                    else:
                        if x not in table:
                            table[x] =[]
                        table[x].append(req_dest['Source Address'][index])
                        count = count + 1
            if (count == 0):
                x = x + 1
                temp.clear()
            else: 
                temp.append(x)
                temp.append(count)
                print(temp)
                writer.writerow(temp)
                temp.clear()
                x = x + 1
    with open('source address to wellknow destinations2222.txt', 'w') as f:
        f.write('all the macthing')
        f.write('\n')
        f.write('\n')
        for x, y in table.items():
            f.write(f"{x} : {y}")
            f.write('\n')
    
    req_dest = pd.read_csv(filename)
    for index in req_dest.index:
        source_port = int(req_dest['Source Port'][index])
        source_ip = req_dest['Source Address'][index]
        if int(req_dest['Source Port'][index]) not in range(0, 1023):
            continue
        else:
            if source_ip not in table2:
                table2[source_ip] = {}
            if source_port not in table2[source_ip]:
                table2[source_ip][source_port] = []
            table2[source_ip][source_port].append(req_dest['Destination Address'][index])
    with open('target address access others.txt', 'w') as f:
        f.write('all the macthing')
        f.write('\n')
        f.write('\n')
        for ip, ports in table2.items():
            for port, addresses in ports.items():
                f.write(f"{ip}-{port}: {addresses}\n")





def run_req_dests(filename):
    print('in run_req_dests\n')
    req_dest = pd.read_csv(filename)
    headers = ['Source Address', 'Source Port', 'Port Name', 'Destination Address', 'Destination Port',
               'Port Name']
    matched = []
    temp = []
    with open('Known ports destination address.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        # print(req_dest)
        for index in req_dest.index:
            # print(req_dest['Source Address'][index])
            ip = req_dest['Source Address'][index]
            ip_port = req_dest['Source Port'][index]
            dest_ip = req_dest['Destination Address'][index]
            dest_port = req_dest['Destination Port'][index]

          
        	
            if check_tcp_known(dest_port) != "unkown":
                temp.append(ip)
                temp.append(ip_port)
                temp.append(check_tcp_known(ip_port))
                temp.append(dest_ip)
                temp.append(dest_port)
                temp.append(check_tcp_known(dest_port))
                writer.writerow(temp)
                print(temp)
                temp.clear()
                matched.clear()


def run_req_src(filename):
    print('in run_req_dests\n')
    req_dest = pd.read_csv(filename)
    headers = ['Source Address', 'Source Port', 'Port Name', 'Destination Address', 'Destination Port',
               'Port Name']
    matched = []
    temp = []
    with open('Known ports destination address(traget address as the destination).csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        # print(req_dest)
        for index in req_dest.index:
            # print(req_dest['Source Address'][index])
            ip = req_dest['Source Address'][index]
            ip_port = req_dest['Source Port'][index]
            dest_ip = req_dest['Destination Address'][index]
            dest_port = req_dest['Destination Port'][index]

          
        	
            if check_tcp_known(dest_port) != "unkown":
                temp.append(ip)
                temp.append(ip_port)
                temp.append(check_tcp_known(ip_port))
                temp.append(dest_ip)
                temp.append(dest_port)
                temp.append(check_tcp_known(dest_port))
                writer.writerow(temp)
                print(temp)
                temp.clear()
                matched.clear()


if __name__ == '__main__':
    print('in the main\n')
    run_req_dests('Required Destination Addresses with VPCs.csv')
    run_req_src('Required Source Addresses with VPCs.csv')
    count_dest_ports('Known ports destination address.csv')
    count_dest_ports_target_dest('Known ports destination address(traget address as the destination).csv')

