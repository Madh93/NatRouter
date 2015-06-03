#!/usr/bin/python
#coding=utf-8

# Ŕyu
from ryu.ofproto import ether
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import (
  ethernet,
  ipv4,
  icmp
)


def build_packet(self, datapath, srcMac, srcIp, dstMac, dstIp, outPort, seq, data, id=1, type=8, ttl=64):

    e = ethernet.ethernet(dstMac, srcMac, ether.ETH_TYPE_IP) #Construye el protocolo ethernet
    iph = ipv4.ipv4(4, 5, 0, 0, 0, 2, 0, ttl, 1, 0, srcIp, dstIp) #Construye la parte del protocolo IP
    echo = icmp.echo(id, seq, data) #Construye la parte del echo que se añadirá al protocolo icmp
    icmph = icmp.icmp(type, 0, 0, echo) #Construye la parte del icmp

    p = Packet() #Crea el paquete
    p.add_protocol(e) #Añade el protocolo ethernet
    p.add_protocol(iph) #Añade el protocolo ip
    p.add_protocol(icmph) #Añade el protocolo icmp
    p.serialize() #Serializa todo

    return p