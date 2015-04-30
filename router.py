#!/usr/bin/python
#coding=utf-8

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.base import app_manager
from ryu.lib import mac
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet_utils
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib import hub
from netaddr.ip import IPNetwork
from netaddr.ip import IPAddress
from ryu.lib.packet.packet import Packet


class SimpleRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    #mac_to_port=dict()
    def __init__(self, *args, **kwargs):
        super(SimpleRouter, self).__init__(*args, **kwargs)
        self.ping_q = hub.Queue()
        self.portInfo = {}
        self.arpInfo = {}
        self.routingInfo = {}
        self.mplsInfo = {}
        
        self.ports_to_ips = [('10.0.0.8','255.255.255.0','00:00:00:00:00:50'),
        ('192.168.1.1','255.255.255.0','00:00:00:00:00:60'),
        ('192.168.2.1','255.255.255.0','00:00:00:00:00:70'),
        ('192.168.3.1','255.255.255.0','00:00:00:00:00:80')]

        self.tablaEnrutamiento = [('10.0.0.1','255.255.255.0',1,None),
        ('10.0.0.2','255.255.255.0',2,None),
        ('10.0.0.3','255.255.255.0',3,None),
        ('10.0.0.4','255.255.255.0',4,None)]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev): #Qué hace el router cuando le llegua un paquete
        print('ENTRO EN LA RUTINA')
        msg = ev.msg 
        datapath = msg.datapath
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']

        packet = Packet (msg.data)
        eth = packet.get_protocol(ethernet.ethernet)
        ethertype = packet.get_protocol(ethernet.ethernet)


        src=eth.src
        dst=eth.dst

        if eth.ethertype==ether.ETH_TYPE_ARP: #Si se trata de un paquete ARPÇ
            arp_msg= packet.get_protocol(arp.arp)
            #print('Mostrar unos cuantos')
            if (arp_msg.dst_ip == self.ports_to_ips[in_port-1][0] and arp_msg.opcode==arp.ARP_REQUEST): #
                print('Entro en el segundo')
                e = ethernet.ethernet(dst=src, src=self.ports_to_ips[in_port-1][2], ethertype=ether.ETH_TYPE_ARP)
                a = arp.arp(opcode=arp.ARP_REPLY, src_mac=self.ports_to_ips[in_port-1][2], src_ip=arp_msg.dst_ip, dst_mac=src, dst_ip=arp_msg.src_ip)
                p = Packet()
                p.add_protocol(e)
                p.add_protocol(a)
                self.send_packet(datapath, in_port,p)
        elif eth.ethertype==ether.ETH_TYPE_IP: #Si se trata de un paquete IP
            #print('paquete ip')
            self.receive_ip(datapath, packet, ethertype, in_port)


    #  Inserta una entrada a la tabla de flujo.
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
            if buffer_id:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                    priority=priority, match=match,
                    instructions=inst, idle_timeout=30,command=ofproto.OFPFC_ADD)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                    match=match, instructions=inst, idle_timeout=30,command=ofproto.OFPFC_ADD)
            #print(mod)
            datapath.send_msg(mod)
            
    # Enviar un paquete construido en el controlador
    # hacia el switch
    def send_packet(self, datapath, port, packet):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        packet.serialize()
        data = packet.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                  buffer_id=ofproto.OFP_NO_BUFFER,
                  in_port=ofproto.OFPP_CONTROLLER,
                  actions=actions,
                  data=data)
        datapath.send_msg(out)

    def receive_ip(self, datapath, packet, etherFrame, inPort): #Función que se usa cuando se recibe un paquete IP
        #print('Hola')
        ipPacket = packet.get_protocol(ipv4.ipv4)
        #print('Fracaso')
        if ipPacket.proto == inet.IPPROTO_ICMP:
            icmpPacket = packet.get_protocol(icmp.icmp)
            self.check_icmp(datapath, etherFrame, ipPacket, icmpPacket, inPort) #Se usa una función que trata un paquete ICMP 
            return 0
        else:
            send_packet(datapath=datapath,port=inPort,packet=packet) #Se envía el paquete
            return 1
    #Función que se encarga de averiguar si se da respuesta al ping y que mensajes se muestran en el router según el tipo
    def check_icmp(self, datapath, etherFrame, ipPacket, icmpPacket, inPort):
        srcMac = etherFrame.src #Dirección MAC de origen
        dstMac = etherFrame.dst #Dirección MAC de destino
        srcIp = ipPacket.src #Dirección IP de origen
        dstIp = ipPacket.dst #Dirección IP de destino
        ttl = ipPacket.ttl #Tiempo de vida
        type = icmpPacket.type #Tipo del paquete icmp (0,3,8,11)
        try:
            id = icmpPacket.data.id #
        except:
            id = 1
        try:
            seq = icmpPacket.data.seq 
        except: 
            seq = 1
        try:
            data = icmpPacket.data.data
        except:
            data = ''
        if icmpPacket.type == 0: #Echo reply. Mensaje generado como respuesta a un mensaje Echo request. Cuando alguien hace ping desde aquí y se recibe la respuesta
            icmp_lenght = ipPacket.total_lenght -20
            buf = ("%d bytes from %s: icmp_req=%d ttl=%d data=[%s]" % (icmp_lenght, srcIp, seq, ttl, data))
            self.ping_q.put(buf)
        elif icmpPacket.type == 3: #Destination Unreachable. 
            buf = "ping (Destination Unreachable )"
            self.ping_q.put(buf)
        elif icmpPacket.type == 8: #Echo request. En este caso se reenvía un echo reply
            self.reply_icmp(datapath, srcMac, dstMac, srcIp, dstIp, ttl, type, id, seq, data, inPort)
        elif icmpPacket.type == 11:
            buf = "ping ( Time Exceeded )"
            self.ping_q.put(buf)
        else:
            buf = "ping ( Unknown reason )"
            self.ping_q.put(buf)
    #Función que se encarga de enviar una réplica de icmp
    def reply_icmp(self, datapath, srcMac, dstMac, srcIp, dstIp, ttl, type, id, seq, data, inPort):
        #Comprobar
        modificado = False
        rutaFinal = IPNetwork('0.0.0.0/0')
        print('Tabla enrutamiento: ')
        print(self.tablaEnrutamiento)
        for ruta in self.tablaEnrutamiento:
            print('RUTA:')
            print(ruta)
            print('DESTINO:')
            print(dstIp)
            if int(IPAddress(ruta[0])) == (int(IPAddress(dstIp)) & int(IPAddress(ruta[1]))):
                print('La dirección se encuentra en la tabla')
                if IPNetwork(ruta[0],ruta[1]).prefixlen > rutaFinal.prefixlen:
                    rutaFinal = IPNetwork(ruta[0],ruta[1])
                    print('Se encuentra la ruta final ')
                    print(rutaFinal)
                    modificado=True
        if(modificado==True):
        	self.send_icmp(datapath, dstMac, dstIp, srcMac, srcIp, inPort, seq, data, id, 0, ttl)
        else:
        	print('No se ha enviado nada')

    def send_icmp(self, datapath, srcMac, srcIp, outPort, seq, data, id=1, type=8, ttl=64):
        print('Entra a enviar el paquete')
        e = ethernet(dstMac, srcMac, ether.ETH_TYPE_IP) #Construye el protocolo ethernet
        iph = ipv4(4, 5, 0, 0, 0, 2, 0, ttl, 1, 0, srcIp, dstIp) #Construye la parte del protocolo IP
        echo = icmp.echo(id, seq, data) #Construye la parte del echo que se añadirá al protocolo icmp
        icmph = icmp.icmp(type, 0, 0, echo) #Construye la parte del icmp

        p = Packet() #Crea el paquete
        p.add_protocol(e) #Añade el protocolo ethernet
        p.add_protocol(iph) #Añade el protocolo ip
        p.add_protocol(icmph) #Añade el protocolo icmp
        p.serialize() #Serializa todo

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)] #Enviar por el puerto outPort
        #Mensaje a enviar
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=p.data)
        print('PAQUETE: ')
        print(out)
        datapath.send_msg(out) #Enviar mensaje

