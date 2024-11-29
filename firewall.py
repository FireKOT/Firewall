from scapy.all import *
import socket
import argparse
import os
import threading


class Rules:

    def __init__(self):

        self.dstIp   = ""
        self.dstPort = ""

        self.srcIp   = ""
        self.srcPort = ""

        self.protocol = ""

        self.access = ""


def getArgs ():

    parser = argparse.ArgumentParser()
    parser.add_argument("-iface1", type = str, default = "eth0")
    parser.add_argument("-iface2", type = str, default = "eth1")
    parser.add_argument("-rules",  type = str, default = "rules.txt")

    return parser.parse_args()


def parseRules (rulesPath: str):

    rulesFile = readRules(rulesPath)

    rules = Rules()

    for rule in rulesFile:

        line = rule.split("#", 1)[0]

        if line.startswith("dstIp"):

            rules.dstIp = line.split()[1]

        elif line.startswith("dstPort"):

            rules.dstPort = line.split()[1]
        
        elif line.startswith("srcIp"):

            rules.srcIp = line.split()[1]

        elif line.startswith("srcPort"):

            rules.srcPort = line.split()[1]

        elif line.startswith("protocol"):

            rules.protocol = line.split()[1]

        elif line.startswith("access"):

            rules.access = line.split()[1]

    return rules


def readRules(rulesPath: str):

    rules = []

    with open(rulesPath, 'r') as file:

        for line in file:
            rules.append(line.strip())

    return rules


def filterPacket (packet, rules):

    eth = Ether(packet)

    dstIp   = ""
    dstPort = ""

    srcIp   = ""
    srcPort = ""

    protocol = ""

    if eth.haslayer(IP):

        ip = eth[IP]

        if ip.haslayer(TCP):

            tcp = ip[TCP]

            dstIp   = ip.dst
            dstPort = tcp.dport

            srcIp   = ip.src
            srcPort = tcp.sprot

            protocol = "TCP"

        elif ip.haslayer(UDP):

            udp = ip[UDP]

            dstIp   = ip.dst
            dstPort = udp.dport

            srcIp   = ip.src
            srcPort = udp.sprot

            protocol = "UDP"

        elif ip.haslayer(ICMP):

            dstIp   = ip.dst
            dstPort = ""

            srcIp   = ip.src
            srcPort = ""

            protocol = "ICMP"

        else:

            return True
    else:

        return True
    
    access = True
    
    if rules.access == "Allow":

        access = True

    elif rules.access == "Deny":

        access = False

    else:

        return False
    
    matchRule = True

    if dstIp != "" and rules.dstIp != "" and (dstIp == rules.dstIp) != access:

        matchRule = False

    if dstPort != "" and rules.dstPort != "" and (dstPort == rules.dstPort) != access:

        matchRule = False

    if srcIp != "" and rules.srcIp != "" and (srcIp == rules.srcIp) != access:

        matchRule = False
    
    if srcPort != "" and rules.srcPort != "" and (srcPort == rules.srcPort) != access:

        matchRule = False

    if protocol != "" and rules.protocol != "" and (protocol == rules.protocol) != access:

        matchRule = False

    return matchRule


def getSocket (iface: str):

    sk = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sk.bind((iface, 0))
    return sk


def firewall (srcSocket, dstSocket, rules):

    while True:

        packet, _ = srcSocket.recvfrom(65535)

        if filterPacket(packet, rules):

            dstSocket.send(packet)


if __name__ == "__main__":

    args = getArgs()

    socket1 = getSocket(args.iface1)
    socket2 = getSocket(args.iface2)

    rules = parseRules(args.rules)

    thread1 = threading.Thread(target = firewall, args=(socket1, socket2, rules))
    thread2 = threading.Thread(target = firewall, args=(socket2, socket1, rules))

    thread1.start()
    thread2.start()

    thread1.join()
    thread2.join()

    socket1.close()
    socket2.close()
    

    