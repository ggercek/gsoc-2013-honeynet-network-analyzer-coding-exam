#!/usr/bin/env python
from scapy.all import *
import csv

if __name__ == '__main__' :
    data={}

    reader = PcapReader('files/http.cap')
    for p in reader :
        key = p.sprintf('{IP:%IP.src%_%IP.dst%} {IP:%IP.dst%_%IP.src%}').split(' ')
        if key: #check empty list
            if data.has_key(key[0]) :
                data[key[0]] += 1
            elif data.has_key(key[1]):
                data[key[1]] += 1
            else :
                # Add key
                data[key[0]] = 1
        else:
            # No IP packet pass it
            pass

    reader.close()
    print 'Data', data

    with open('files/output.csv', 'wb') as csvfile:
        writer = csv.writer(csvfile, quotechar='\'', delimiter=',', quoting=csv.QUOTE_MINIMAL)
        for key, val in data.iteritems():
            src, dst = key.split('_')
            writer.writerow([src, dst, val])