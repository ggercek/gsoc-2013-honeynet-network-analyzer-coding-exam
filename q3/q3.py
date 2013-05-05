#!/usr/bin/env python
import sys
sys.path.append('../dissectors')
from dissector import *

import argparse
import datetime
from scapy.all import *
from irc import IRCReq, IRCRes

class IRCAnalyzer() :
    """A Simple class to parse pcap files and extract irc messages to given file."""
    def __init__(self):
        self.outFiles={}
        pass


    def start(self, inputFile, outputFolder):
        """
        Reads the input pcap file and writes the irc messages with timestamp to file.
        @param inputFile: input pcap file to read the irc traffic
        @param outputFolder: output Folder to write session files
        """

        # Use dissector to build up streams
        d = Dissector()
        d.dissect_pkts(inputFile)
        sessions = d.sessions

        self.outFiles = {}
        for s in sessions :
            # Save sessions into separate files
            # TODO: Remove non IRC traffic files. Those files are empty...
            src = s[0]
            dst = s[1]
            sport = s[2]
            dport = s[3]

            filename = '%s_%d_%s_%d'%(src, sport, dst, dport)
            filename2 = '%s_%d_%s_%d'%(dst, dport, src, sport)
            if not self.outFiles.has_key(filename):
                if not self.outFiles.has_key(filename2):
                    f = open(outputFolder + '/' + filename, 'w')
                    self.outFiles[filename] = f
                else:
                    pass
            else:
                pass

        reader = PcapReader(inputFile)
        # TODO: No need to loop twice! Change the dissector code to add application protocol information to Stream class
        for p in reader:
            req = p.getlayer(IRCReq)
            res = p.getlayer(IRCRes)
            ts = datetime.datetime.fromtimestamp(p.time).strftime('%Y-%m-%d %H:%M:%S.%f')
            direction = p.sprintf('{TCP:%r,IP.src%:%r,TCP.sport% -> %r,IP.dst%:%r,TCP.dport%}')

            if req:
                outfile = self._getOutfile(p)
                outfile.write('[' + ts + ' - ' + direction + '] ' + str(req.fields) + '\n')
                outfile.flush()
            elif res:
                outfile = self._getOutfile(p)
                outfile.write('[' + ts + ' - ' + direction + '] ' + str(res.fields) + '\n')
                outfile.flush()

        reader.close()

        for outFile in self.outFiles.values():
            outFile.flush()
            outFile.close()

    def _getOutfile(self, packet):
        """
        Returns the open file objects to given packet
        @param packet: a scapy packet object with IP and TCP layers, otherwise function will return None
        """
        key = packet.sprintf('{TCP:%r,IP.src%_%r,TCP.sport%_%r,IP.dst%_%r,TCP.dport%} {IP:%r,IP.dst%_%r,TCP.dport%_%r,IP.src%_%r,TCP.sport%}').split(' ')
        if key: #check empty list
            if self.outFiles.has_key(key[0]):
                return self.outFiles[key[0]]
            elif self.outFiles.has_key(key[1]):
                return self.outFiles[key[1]]
        return None

def main():
    """Parse the command line arguments and start the analyzer"""
    parser = argparse.ArgumentParser(description='A simple tool for parsing IRC traffic from given pcap file')
    parser.add_argument('-i','--input', help='Input file name', required=True)
    parser.add_argument('-o','--output', help='Output folder name', required=True)
    args = parser.parse_args()

    analyzer = IRCAnalyzer()
    analyzer.start(args.input, args.output)

if __name__ == '__main__':
    # Sample usage: q3.py -i ../files/SkypeIRC.cap -o output
    main()