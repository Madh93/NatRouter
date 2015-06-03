#!/usr/bin/python
#coding=utf-8

# Ŕyu
from ryu.ofproto import ether
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import (
    arp,
    ethernet
)


def build_packet(proto=None, etherFrame=None, srcMac=None, srcIp=None, dstIp=None):

    # Si existe el paquete, es que se esta solicitando una RESPUESTA
    if proto
        e = ethernet.ethernet(dst=etherFrame.src,
                              src=srcMac,
                              ethertype=ether.ETH_TYPE_ARP)
        a = arp.arp(opcode=arp.ARP_REPLY,
                    src_mac=srcMac,
                    src_ip=proto.dst_ip,
                    dst_mac=etherFrame.src,
                    dst_ip=proto.src_ip)

    # En caso contrario se quiere crear un paquete
    else
        e = ethernet.ethernet(src=etherFrame.dst, ethertype=ether.ETH_TYPE_ARP)
        a = arp.arp(opcode=arp.ARP_REQUEST,
                    src_mac=etherFrame.src,
                    src_ip=srcIp,
                    dst_ip=dstIp)        

    p = Packet()
    p.add_protocol(e)
    p.add_protocol(a)

    return p