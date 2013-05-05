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
        pass


    def start(self, inputFile, outputFile):
        """
        Reads the input pcap file and writes the irc messages with timestamp to file.
        @param inputFile: input pcap file to read the irc traffic
        @param outputFile: clear text file to write the messages
        """
        reader = PcapReader(inputFile)

        with open(outputFile, 'wb') as outFile:
            for p in reader:
                req = p.getlayer(IRCReq)
                res = p.getlayer(IRCRes)
                ts = datetime.datetime.fromtimestamp(p.time).strftime('%Y-%m-%d %H:%M:%S.%f')
                # TODO: Seperate sessions
                if req:
                    outFile.write(str(req.fields) + '\n')
                if res:
                    outFile.write(str(res.fields) + '\n')

            reader.close()
            outFile.flush()


def main():
    """arse the command line arguments and start the analyzer"""
    parser = argparse.ArgumentParser(description='A simple tool for parsing IRC traffic from given pcap file')
    parser.add_argument('-i','--input', help='Input file name',required=True)
    parser.add_argument('-o','--output',help='Output file name', required=True)
    args = parser.parse_args()

    analyzer = IRCAnalyzer()
    analyzer.start(args.input, args.output)


if __name__ == '__main__':
    # Sample usage: q3.py -i ../files/SkypeIRC.cap -o sampleOutputIRC.txt
    main()