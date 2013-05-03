import sys
sys.path.append('../dissectors')

from scapy.all import *
from dissector import *
from irc import IRCReq, IRCRes


if __name__ == '__main__' :
    reader = PcapReader('../files/SkypeIRC.cap')

    with open('sampleOutputIRC.txt', 'wb') as outFile:
        for p in reader:
            req = p.getlayer(IRCReq)
            res = p.getlayer(IRCRes)
            if req:
                outFile.write(str(req.fields) + '\n')
            if res:
                outFile.write(str(res.fields) + '\n')

        reader.close()
        outFile.flush()

