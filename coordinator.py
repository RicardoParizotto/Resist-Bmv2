#!/usr/bin/env python3
import os
import sys
import time
import ast


from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp

from scapy.all import (
    TCP,
    FieldLenField,
    FieldListField,
    IntField,
    IPOption,
    ShortField,
    get_if_list,
    sniff
)
from scapy.layers.inet import _IPOption_HDR

import threading

from resist_header import *

/*TODO: collect round number at the coordinator ,
replay based on the round received,
send signal to nodes to restart
implement send back to replica in the switches
inject a failure in the main switch*/


PKT_FROM_SHIM_LAYER = 0
PKT_FROM_MASTER_TO_REPLICA =  1
PKT_PING = 2
PKT_PONG = 3
REQUEST_DATA = 4
REPORT_DATA = 5
REPLAY_DATA = 6
PKT_COLLECT_ROUND = 10

class coordinator:
    def __init__(self):
        self.ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
        for i in self.ifaces:
            if "eth0" in i:
                self.iface=i
                break;

        self.nodes = {"1": "10.0.1.1", "2": "10.0.2.2"}

        self.inputPerNode = {}
        self.collectCounter = 0
        self.replayInput = {}
        #self.nu_until_collect = #threading.Lock()

        #pick an interface. IT should be eth0
        self.ifaces.remove(self.iface) #removes eth0 from the interface

        self.master_alive = True  #it starts with the master alive


        self.receiveThread = threading.Thread(target = self.receive)
        self.receiveThread.start()

        self.heartbeatingThread = threading.Thread(target = self.heartbeating)
        self.heartbeatingThread.start()

    def collect_state(self):
        #send message to all the nodes for requesting logs
        for i in self.nodes:
            pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff')
            pkt =  pkt / ResistProtocol(flag=REQUEST_DATA) / IP(dst= self.nodes[i])
            sendp(pkt, iface=self.iface, verbose=False)
        #Note: Using the receive thread to receive from all the hosts

        pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff')
        pkt =  pkt / ResistProtocol(flag=PKT_COLLECT_ROUND) / IP(dst= self.nodes[i])
        sendp(pkt, iface=self.iface, verbose=False)
        #after all the nodes answer
        while (self.collectCounter < len(self.nodes)):
            time.sleep(0.1)
            #this is not how it should be done
        self.aggregateAndComputeState()

    def aggregateAndComputeState(self):
        print(self.inputPerNode)
        for node in self.inputPerNode.keys():
            #TODO: add to a map per nodes
            #for messages from every node
            for msg in self.inputPerNode[node]:
                #if the ID is not know by the replayInput data structure
                if msg['pid'] not in self.replayInput.keys():
                    self.replayInput[msg['pid']] = []
                #if the specific LVT is not in the set of messages that pid has to replay, include this message and its round number to the set
                if msg['lvt'] not in self.replayInput[msg['pid']]:
                    self.replayInput[msg['pid']].append(msg)

    #    print(self.replayInput)

        for node in self.replayInput.keys():
            print(self.replayInput)
            pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff')
            pkt =  pkt / ResistProtocol(flag=REPLAY_DATA) / IP(dst= self.nodes[str(node)])
            pkt = pkt / Raw(load=str(self.replayInput[node]))
            sendp(pkt, iface=self.iface, verbose=False)



    def receive_host_state(self):
        print("sniffing on %s" % iface)
        sys.stdout.flush()
        sniff(iface = self.iface,
              prn = lambda x: self.handle_pkt(x))

    def handle_pkt(self, pkt):
        if ResistProtocol in pkt and pkt[ResistProtocol].flag == PKT_PONG:
            print("pong")
            #pkt.show2()
            self.master_alive = True
            sys.stdout.flush()
        if ResistProtocol in pkt and pkt[ResistProtocol].flag == REPORT_DATA:
            if Raw in pkt:
                self.inputPerNode[pkt[ResistProtocol].pid] = eval(pkt[Raw].load)
                self.collectCounter = self.collectCounter + 1

    def heartbeating(self):
        while True:
            time.sleep(5)
            if(self.master_alive):
                self.master_alive = False
                pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type=TYPE_RES)
                pkt = pkt / ResistProtocol(flag=PKT_PING) / IP(dst="10.0.1.1")
                #pkt.show2()
                print("ping")
                sendp(pkt, iface=self.iface, verbose=False)
            else:
                #TODO:I need to trigger the recovery process on shim layers
                self.change_interface()
                self.master_alive = True

                self.collect_state()
                #necessario para nao entrar nessa condicao logo que o novo leader e escolhido
                #envia pacote de start change
                #pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type = TYPE_RES)
                #pkt = pkt / ResistProtocol(flag = MASTER_CHANGE)
                #sendp(pkt, iface=self.iface, verbose=False)

    def change_interface(self):
        print(('PRIMARY TIMEOUT!!!' + str(self.ifaces)))
        for i in self.ifaces:
            if i:
                self.iface = i
                self.ifaces.remove(i)
                break
        self.receiveThread = threading.Thread(target = self.receive)
        self.receiveThread.start()


    def receive(self):
        print("sniffing on %s" % self.iface)
        sys.stdout.flush()
        sniff(iface = self.iface,
              prn = lambda x: self.handle_pkt(x))

    def get_if(self):
        ifs=get_if_list()
        iface=None
        for i in get_if_list():
            if "eth0" in i:
                iface=i
                break;
        if not iface:
            print("Cannot find eth0 interface")
            exit(1)
        return iface


if __name__ == '__main__':
    coordinator()
