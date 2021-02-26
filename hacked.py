#!/usr/bin/python3
import os
import shlex
import json
from datapackage import Package

package = Package('https://datahub.io/core/country-list/datapackage.json')

# print processed tabular data (if exists any)
for resource in package.resources:
    if resource.descriptor['datahub']['type'] == 'derived/csv':
        countryList = resource.read()
countryDict = d={x[1]:x[0] for x in countryList}

def GetHacks(IPlist):
    from ipwhois import IPWhois
    
    countryHacks = {}
    for n in range(0, len(IPlist), 2):
        count, ip = IPlist[n:n + 2]

        if ip != '0.0.0.0' and ip[0:7] != '192.168':
            try:
                domain = IPWhois(ip)
                pwy = domain.lookup_rdap()
                country = pwy['asn_country_code']
                countryName = countryDict[country]
            except:
                country = 'Invalid'
                countryName = "Invalid IP address"
        else:
            country = 'Home'
            countryName = "Home"

        print(ip + " attempted " + count + " hacks from " + countryName)

        x = countryHacks.get(countryName)
        if x:
            countryHacks.update({countryName: x + int(count)})
        else:
            countryHacks.update({countryName: int(count)})
    print()

    print("Total attacks by country:")
    print("-------------------------")
    for a, b in countryHacks.items():
        print(str(b) + " hacks from " + a)

    print("\nTotal global attacks: " + str(sum(countryHacks.values())))
    print()


# sshd messages
stream1 = os.popen("journalctl _COMM=sshd --since=yesterday --until=today | grep 'Failed password for invalid user' | awk '{print $13}'|sort|uniq -c|sort -n")
output1 = stream1.read()
iplist1 = shlex.split(output1)
stream2 = os.popen("journalctl _COMM=sshd --since=yesterday --until=today | grep 'Failed password for'| grep -v 'invalid user' | awk '{print $11}'|sort|uniq -c|sort -n")
output2 = stream2.read()
iplist2 = shlex.split(output2)

print("Brute Force Attacks")
print("-------------------")
GetHacks(iplist1 + iplist2)

# nginx messages
print("Web Page Attacks")
print("----------------")
stream = os.popen(
    "grep -o '^[0-9]\{1,3\}\.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}' /var/log/nginx/access.log |sort|uniq -c"
)
output = stream.read()
iplist = shlex.split(output)
GetHacks(iplist)
