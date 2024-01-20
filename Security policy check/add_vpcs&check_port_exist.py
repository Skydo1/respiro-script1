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
            found.append(tcp)
    if found:
        return tcp
    else:
        return 'unknown'

def run_req_dests(filename):
    print('in run_req_dests\n')
    req_dest = pd.read_csv(filename)
    vpcs = pd.read_csv('VPCs.csv')
    headers = ['Source Address', 'Source Port', 'Port Name', 'Destination Address', 'Destination Port',
               'Port Name', 'VPC Name']

    matched = []
    temp = []
    global unknown_address
    with open('Required Destination Addresses with VPCs.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        # print(req_dest)
        for index in req_dest.index:
            # print(req_dest['Source Address'][index])
            ip = req_dest['Src Address'][index]
            ip_port = req_dest['Src Port'][index]
            dest_ip = req_dest['Dst Address'][index]
            dest_port = req_dest['Dst Port'][index]

            # print(ip)
            # print(type(ip))
            for x in vpcs.index:
                #print(vpcs['VPC CIDR'][x])
                if ipaddress.ip_address(dest_ip) in ipaddress.ip_network(vpcs['VPC CIDR'][x]):
                    #print('match found for: ', dest_ip, ' in: ', vpcs['VPC CIDR'][x])
                    vpc = vpcs['VPC CIDR'][x]
                    matched.append(vpc)
                else:
                    unknown_address.append(dest_ip)
            if matched:
                #print('Matched found', matched)
                temp.append(ip)
                temp.append(ip_port)
                #check
                temp.append(check_tcp_known(ip_port))

                temp.append(dest_ip)
                temp.append(dest_port)
                # check
                temp.append(check_tcp_known(dest_port))

                temp.append(matched)
                #print('printing temp', temp)
                writer.writerow(temp)

                temp.clear()
                matched.clear()
            else:
                temp.append(ip)
                temp.append(ip_port)
                temp.append(check_tcp_known(ip_port))

                temp.append(dest_ip)
                temp.append(dest_port)
                temp.append(check_tcp_known(dest_port))

                matched.append('Internet')
                temp.append(matched)
                writer.writerow(temp)
                temp.clear()
                matched.clear()


def run_req_src(filename):
    print('in run_req_src\n')
    req_src = pd.read_csv(filename)
    vpcs = pd.read_csv('VPCs.csv')
    tcp_ports = pd.read_csv('tcp.csv')
    headers = ['Source Address', 'Source Port', 'Port Name', 'Destination Address', 'Destination Port',
               'Port Name', 'VPC Name']
    temp = []
    matched = []
    global unknown_address
    with open('Required Source Addresses with VPCs.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(headers)


        for index in req_src.index:
            ip = req_src['Dst Address'][index]
            ip_port = req_src['Dst Port'][index]
            # print(ip)
            src_ip = req_src['Src Address'][index]
            src_ip_port = req_src['Src Port'][index]

            for x in vpcs.index:
                # print(vpcs['VPC CIDR'][x])
                if ipaddress.ip_address(ip) in ipaddress.ip_network(vpcs['VPC CIDR'][x]):
                    #print('match found for: ', ip, ' in VPC: ', vpcs['VPC CIDR'][x])
                    vpc = vpcs['VPC CIDR'][x]
                    matched.append(vpc)
                else:
                    unknown_address.append(src_ip)
            if matched:
                #print('Matched found', matched)
                temp.append(src_ip)
                temp.append(src_ip_port)
                # check tcp known or not
                temp.append(check_tcp_known(src_ip_port))
                temp.append(ip)
                temp.append(ip_port)
                #check
                temp.append(check_tcp_known(ip_port))
                temp.append(matched)
                #print('printing temp', temp)
                writer.writerow(temp)

                temp.clear()
                matched.clear()
            else:
                temp.append(src_ip)
                temp.append(src_ip_port)
                temp.append(ip)
                temp.append(ip_port)
                matched.append('Internet')
                temp.append(matched)
                writer.writerow(temp)
                temp.clear()
                matched.clear()


def test_ip():
    sub = '192.168.0.0/24'
    ip = '192.168.0.1'
    if ipaddress.ip_address(ip) in ipaddress.ip_network(sub):
        print('matched')


def count_VPCs():
    print('in count_VPCs\n')
    req_src = 'Required Source Addresses with VPCs.csv'
    req_dst = 'Required Destination Addresses with VPCs.csv'
    vpcs = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "141.243.0.0/16",
        "148.145.0.0/16",
        "203.11.147.0/24",
        "203.11.144.0/24",
        "203.11.145.0/24",
        "10.250.224.0/20",
        "10.246.64.0/20",
        "10.251.112.0/20",
        "10.251.0.0/20",
        "10.246.48.0/20",
        "10.251.144.0/20",
        "10.250.112.0/20",
        "10.247.20.0/22",
        "10.251.48.0/20",
        "10.250.128.0/20",
        "10.246.224.0/20",
        "10.250.0.0/20",
        "10.250.208.0/20",
        "10.246.240.0/20",
        "10.250.32.0/20",
        "10.251.16.0/20",
        "10.245.24.0/21",
        "10.250.48.0/20",
        "10.251.96.0/20",
        "10.245.192.0/19",
        "10.251.128.0/20",
        "10.246.56.0/21",
        "10.245.80.0/20",
        "10.247.24.0/22",
        "10.246.48.0/21",
        "10.245.176.0/20",
        "10.245.224.0/20",
        "10.250.192.0/20",
        "10.250.64.0/20",
        "10.247.28.0/22",
        "10.251.32.0/20",
        "10.245.112.0/20",
        "10.246.96.0/20",
        "10.245.96.0/20",
        "10.249.0.0/16"


    ]
    src = pd.read_csv(req_src)
    dst = pd.read_csv(req_dst)

    # print(src)
    # print(dst)

    # for items in vpcs:
    #     print('*********************')
    #     print(items, type(items))
    #     print('*********************')

    # for items in src.index:
    #     print('*********************')
    #     print(src['VPC Name'][items], type(src['VPC Name'][items]))
    #     print('*********************')

    src_vpcs = []
    dst_vpcs = []
    count = 0

    # print('********************** Counting VPC occurrence of VPCs in Required Source Addresses with VPCs '
    #       '**********************')
    for items in vpcs:
        # print('items: ', items)
        for index in src.index:
            # print('src[VPC Name][index]: ', src['VPC Name'][index])
            if items in src['VPC Name'][index]:
                count += 1
        # print(count)
        src_vpcs.append(count)
        count = 0

    # this is counting VPC occurrence of VPCs in Required Source Addresses with VPCs

    for x in range(len(vpcs)):
        print(vpcs[x], ' : ', src_vpcs[x])

    # print('********************** Counting VPC occurrence of VPCs in Required Destination Addresses with VPCs '
    #       '**********************')
    for items in vpcs:
        # print('items: ', items)
        for index in dst.index:
            # print('dst[VPC Name][index]: ', dst['VPC Name'][index])
            if items in dst['VPC Name'][index]:
                count += 1
        # print(count)
        dst_vpcs.append(count)
        count = 0

    print('\n************************************************************\n')

    # this is counting VPC occurrence of VPCs in Required Source Addresses with VPCs

    for x in range(len(vpcs)):
        print(vpcs[x], ' : ', dst_vpcs[x])

    # now we write the summary file
    with open('VPCs Summary.txt', 'w') as f:
        f.write('VPC count for the Required Source Addresses with VPCs file')
        f.write('\n')
        f.write('\n')
        for x in range(len(vpcs)):
            if vpcs[x] == '10.250.224.0/20':
                f.write(vpcs[x])
                f.write('  dpifishnonprodVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.246.64.0/20':
                f.write(vpcs[x])
                f.write('  dreqaVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.251.112.0/20':
                f.write(vpcs[x])
                f.write('  nownonprodVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.251.0.0/20':
                f.write(vpcs[x])
                f.write('  bsfanonprodVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.246.48.0/20':
                f.write(vpcs[x])
                f.write('  dreqaVPC2')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.251.144.0/20':
                f.write(vpcs[x])
                f.write('  epanonprodVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.250.112.0/20':
                f.write(vpcs[x])
                f.write(' dpiagVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.247.20.0/22':
                f.write(vpcs[x])
                f.write('  kmnonprod-vpc01')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.251.48.0/20':
                f.write(vpcs[x])
                f.write('  dpinonprodVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.250.128.0/20':
                f.write(vpcs[x])
                f.write('  dpifishVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.246.224.0/20':
                f.write(vpcs[x])
                f.write('  finnonprodVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.250.0.0/20':
                f.write(vpcs[x])
                f.write('  lgnswprodVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.250.208.0/20':
                f.write(vpcs[x])
                f.write('  crownlandsnonprodVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.246.240.0/20':
                f.write(vpcs[x])
                f.write('  kmprodVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.250.32.0/20':
                f.write(vpcs[x])
                f.write('  llsVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.251.16.0/20':
                f.write(vpcs[x])
                f.write('  bsfaprodVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.245.24.0/21':
                f.write(vpcs[x])
                f.write('  external perimeter')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.250.48.0/20':
                f.write(vpcs[x])
                f.write('  llsnonprodVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.251.96.0/20':
                f.write(vpcs[x])
                f.write('  nowprodVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.245.192.0/19':
                f.write(vpcs[x])
                f.write('  wksprodVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.251.128.0/20':
                f.write(vpcs[x])
                f.write('  epaprodVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.246.56.0/21':
                f.write(vpcs[x])
                f.write('  megnonprodVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.245.80.0/20':
                f.write(vpcs[x])
                f.write('  Shared VPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.247.24.0/22':
                f.write(vpcs[x])
                f.write('  MulesoftProd')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.246.48.0/21':
                f.write(vpcs[x])
                f.write('  megprodVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.245.176.0/20':
                f.write(vpcs[x])
                f.write('  osbcdevVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.245.224.0/20':
                f.write(vpcs[x])
                f.write('  finprodVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.251.32.0/20':
                f.write(vpcs[x])
                f.write('  dpiprodVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.250.192.0/20':
                f.write(vpcs[x])
                f.write('  crownlandsprodVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.250.64.0/20':
                f.write(vpcs[x])
                f.write('  dmz2VPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.247.28.0/22':
                f.write(vpcs[x])
                f.write('  Mulesoft')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.245.112.0/20':
                f.write(vpcs[x])
                f.write('  DevVpc')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.246.96.0/20':
                f.write(vpcs[x])
                f.write(' faprodVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.245.96.0/20':
                f.write(vpcs[x])
                f.write('  QAVPC')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            elif vpcs[x] == '10.249.0.0/16':
                f.write(vpcs[x])
                f.write('  tradevpc')
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
            else:
                f.write(vpcs[x])
                f.write(' : ')
                f.write(str(src_vpcs[x]))
                f.write('\n')
        f.write('Total: ')
        f.write(str(len(src.index)))

        f.write('\n')
        f.write('\n')

        f.write('VPC count for the Required Destination Addresses with VPCs file')
        f.write('\n')
        f.write('\n')

        for x in range(len(vpcs)):
            f.write(vpcs[x])
            f.write(' : ')
            f.write(str(dst_vpcs[x]))
            f.write('\n')
        f.write('Total: ')
        f.write(str(len(dst.index)))

def run_nslookup():
    unknown = list(dict.fromkeys(unknown_address))
    print(unknown)
    #print("frnwfrirehghiurehgiuregreiugejvrevpokekregopkrejoigoijd;oivnpuehgew")

    headers = ['Address', 'registrar', 'name', 'country']
    with open('unknown addresses.csv', 'w', newline=''  ) as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        for index in unknown:
            try:
                w = IPWhois(index).lookup_rdap()
                found = w["asn_description"]
                company, location = map(str.strip, found.split(','))
                writer.writerow([index, w["asn_registry"],company,location])
            except IPDefinedError as e:
                writer.writerow([index, "unknown", "unknown", "unknown"])
            except Exception as e:
                writer.writerow([index, "unknown", "unknown", "unknown"])



if __name__ == '__main__':
    print('in the main\n')
    run_req_dests('Required Destination Addresses (No Dupes).csv')
    #test_ip()
    run_req_src('Required Source Addresses (No Dupes).csv')
    count_VPCs()
    run_nslookup()
