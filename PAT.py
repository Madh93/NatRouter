#!/usr/bin/python
#coding=utf-8

# Ŕyu
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
  set_ev_cls,
  CONFIG_DISPATCHER,
  MAIN_DISPATCHER
)
from ryu.ofproto import (
  ofproto_v1_3,
  ether,
  inet
)
from ryu.lib.packet import (
  packet,
  ethernet,
  ipv4,
  arp,
  icmp,
  tcp,
  udp,
  packet_utils
)
from ryu.lib.packet.packet import Packet
from ryu.lib import hub
# Netaddr
from netaddr.ip import (
  IPAddress,
  IPNetwork
)
# Otros
import random
ip_publica = '10.0.0.69'

class Router(app_manager.RyuApp):

    # mac_to_port=dict()
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Router, self).__init__(*args, **kwargs)
        self.ping_q = hub.Queue()
        self.ipToMac = dict()
        self.portsToIps = [('10.0.0.69','255.255.255.0','00:00:00:00:00:50'),
                             ('10.0.1.1','255.255.255.0','00:00:00:00:00:60')]
        self.tablaEnrutamiento = [('10.0.0.0','255.255.255.0',1,None),
                                  ('10.0.1.0','255.255.255.0',2,None)]
        self.tablaNat = [] #[ip_privada(src), puerto_privado(src_port), ip_publica(dst), puerto_publico(dst_port), mac_origen]
        self.used_ports = []
        self.cachePendientes = dict()

    # Devuelve la red correspondiente (IPNetwork(ipaddres/mask))
    def find_in_routingTable (self, dstIp):
        ruta_sel = [IPNetwork('0.0.0.0/0'),0,None]
        for ruta in self.tablaEnrutamiento:
            if IPAddress(ruta[0]) == (IPAddress(dstIp) & IPAddress(ruta[1])):
                if int(ruta_sel[0].prefixlen) < int(IPAddress(ruta[1])):
                    ruta_sel[0] = IPNetwork(ruta[0],ruta[1])    #Network
                    ruta_sel[1] = ruta[2]                       #Puerto
                    ruta_sel[2] = ruta[3]                       #Gateway
        if ruta_sel[2] == None:
            return (dstIp, ruta_sel[1])
        else:
            return (ruta[ruta_sel[2]], ruta_sel[1])        

    #---------------------------------------------#
    # Gestión de los paquetes entrantes al Router #
    #---------------------------------------------#
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev): 
        msg = ev.msg 
        datapath = msg.datapath
        in_port = msg.match['in_port']        
        packet = Packet(msg.data)
        eth = packet.get_protocol(ethernet.ethernet)
        src = eth.src
        dst = eth.dst
        if eth.ethertype == ether.ETH_TYPE_ARP: #Si se trata de un paquete ARP
            self.receive_arp(datapath=datapath, packet=packet, etherFrame=eth, inPort=in_port)
        elif eth.ethertype == ether.ETH_TYPE_IP: #Si se trata de un paquete IP
            cabecera_ip = packet.get_protocol(ipv4.ipv4)
            self.ipToMac[cabecera_ip.src] = src
            try: #Intenta almacenar un paquete del tipo TCP
                cabecera_tcp = packet.get_protocol(tcp.tcp)
            except:
                pass
            try: #Intenta almacenar un paquete del tipo UDP
                cabecera_udp = packet.get_protocol(udp.udp)
            except:
                pass
            if packet.get_protocol(tcp.tcp):    #Paquete TCP
                self.nat(in_port=in_port, cabecera=cabecera_tcp, cabecera_ip=cabecera_ip, datapath=datapath, msg=msg)
            elif packet.get_protocol(udp.udp):  #Paquete UDP
                self.nat(in_port=in_port, cabecera=cabecera_udp, cabecera_ip=cabecera_ip, datapath=datapath, msg=msg)
            else:    #Se trata de un paquete ICMP
                self.receive_ip(datapath=datapath, packet=packet, etherFrame=eth, inPort=in_port, msg=msg)

    #----------------------------------------------------------#
    # Procesar si se trata de una respuesta o una peticion ARP #
    #----------------------------------------------------------#
    def receive_arp(self, datapath, packet, etherFrame, inPort):
        arp_msg = packet.get_protocol(arp.arp)
        if arp_msg.opcode == arp.ARP_REQUEST:
            if arp_msg.dst_ip == self.portsToIps[inPort-1][0]:
                p = self.build_arp(proto=arp_msg, etherFrame=etherFrame, srcMac=self.portsToIps[inPort-1][2])
                self.send_packet(datapath, inPort, p)
        elif arp_msg.opcode == arp.ARP_REPLY:
            self.ipToMac[arp_msg.src_ip] = arp_msg.src_mac
            for (msg,port,nat,puertoNat) in self.cachePendientes[arp_msg.src_ip]:
                if nat == None and puertoNat == None:
                    self.insertar_flujo(msg=msg, mac=arp_msg.src_mac, port=port, mod=1)
                elif nat == 1:
                    self.insertar_flujo(msg=msg, mod=0, puerto_origen=puertoNat, ip_origen=ip_publica, sentido=1, protoc=1, port=port, mac=arp_msg.src_mac)
            self.cachePendientes[arp_msg.src_ip] = []

    def build_arp(self, proto=None, etherFrame=None, srcMac=None, srcIp=None, dstIp=None):
        # Si existe el paquete, es que se esta solicitando una RESPUESTA
        if proto:
            e = ethernet.ethernet(dst=etherFrame.src,
                                  src=srcMac,
                                  ethertype=ether.ETH_TYPE_ARP)
            a = arp.arp(opcode=arp.ARP_REPLY,
                        src_mac=srcMac,
                        src_ip=proto.dst_ip,
                        dst_mac=etherFrame.src,
                        dst_ip=proto.src_ip)
        # En caso contrario se quiere crear un paquete
        else:
            e = ethernet.ethernet(src=etherFrame.dst, ethertype=ether.ETH_TYPE_ARP)
            a = arp.arp(opcode=arp.ARP_REQUEST,
                        src_mac=etherFrame.src,
                        src_ip=srcIp,
                        dst_ip=dstIp)        
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        return p

    #---------------------------------------------------#
    # Función que se usa cuando se recibe un paquete IP #
    #---------------------------------------------------#
    def receive_ip(self, datapath, packet, etherFrame, inPort, msg):
        ipPacket = packet.get_protocol(ipv4.ipv4)
        #Si va destinado al router
        if ipPacket.dst == self.portsToIps[0][0]:
            if ipPacket.proto == inet.IPPROTO_ICMP:
                icmpPacket = packet.get_protocol(icmp.icmp)
                self.check_icmp(datapath, etherFrame, ipPacket, icmpPacket, inPort) #Se usa una función que trata un paquete ICMP 
            else:
                send_packet(datapath=datapath,port=inPort,packet=packet) #Se envía el paquete
        #Si no va destinado al router
        else:
            (next_hop, port) = self.find_in_routingTable(ipPacket.dst) #Almacena el puerto y el siguiente salto
            #en port y en next_hop
            if next_hop in self.ipToMac.keys(): #Si está dentro de la tabla de ips y macs se envía.
                match = datapath.ofproto_parser.OFPMatch(eth_dst=self.ipToMac[next_hop]) 
                actions = [datapath.ofproto_parser.OFPActionOutput(port)]
                self.insertar_flujo(msg=msg, mac=self.ipToMac[next_hop], port=port, mod=1)
            else: #Si no está dentro de la tabla se construye un paquete ARP para averiguar su MAC
                p = build_arp(srcIp=self.portsToIps[port-1][0], dstIp=next_hop)
                if next_hop not in self.cachePendientes:
                    self.cachePendientes[next_hop] = []
                self.cachePendientes[next_hop] = self.cachePendientes[next_hop] + [(msg, port,None,None)]
                self.send_packet(datapath=datapath, port=port, packet=p)    

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
            icmp_length = ipPacket.total_length -20
            buf = ("%d bytes from %s: icmp_req=%d ttl=%d data=[%s]" % (icmp_length, srcIp, seq, ttl, data))
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
        if self.find_in_routingTable(dstIp):
            self.send_icmp(datapath, dstMac, dstIp, srcMac, srcIp, inPort, seq, data, id, 0, ttl)
        else:
            print('No se ha enviado nada')

    def send_icmp(self, datapath, srcMac, srcIp, dstMac, dstIp, outPort, seq, data, id=1, type=8, ttl=64):
        e = ethernet.ethernet(dstMac, srcMac, ether.ETH_TYPE_IP) #Construye el protocolo ethernet
        iph = ipv4.ipv4(4, 5, 0, 0, 0, 2, 0, ttl, 1, 0, srcIp, dstIp) #Construye la parte del protocolo IP
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
        datapath.send_msg(out) #Enviar mensaje           

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
            datapath.send_msg(mod)

    #----------------------------------------------------------------#
    # Enviar un paquete construido en el controlador hacia el switch #
    #----------------------------------------------------------------#
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

    def insertar_en_cola(self, ip, puerto, msg, nat=None, puertoNat=None):
        if ip not in self.cachePendientes:  
            self.cachePendientes[ip] = []
        self.cachePendientes[ip] = self.cachePendientes[ip]+[(msg,puerto,nat,puertoNat)]

    def enviar_arp(self, mac_origen, port, next_hop, datapath, msg, nat=None, puertoNat=None):
        e = ethernet.ethernet(src=mac_origen, ethertype=ether.ETH_TYPE_ARP)
        a = arp.arp(opcode=arp.ARP_REQUEST,
            src_ip=self.portsToIps[port-1][0],
            src_mac=mac_origen,
            dst_ip=next_hop)
        #puerto = mac_origen
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        self.insertar_en_cola(ip=next_hop, puerto=port, msg=msg, nat=nat, puertoNat=puertoNat)
        self.send_packet(datapath=datapath, port=port, packet=p)

    def nat(self, in_port, cabecera, cabecera_ip, datapath, msg):
        #ALMACENAR LA INFORMACIÓN EN LA TABLA:
                esta_en_tabla = False
                fila = None
                red_privada = True
                if in_port in [2,3,4]: #Si pertenece a la red privada
                    for em in self.tablaNat: #Busca en la tabla por Ip origen ?? #PUERTO DE ORIGEN
                        if ((cabecera_ip.src == em[0]) and (cabecera.src_port == em[1])):
                            esta_en_tabla = True
                            fila = em
                else: #Si pertenece a la red pública
                    red_privada = False
                    for em in self.tablaNat: #Busca en la tabla por puerto destino ??
                        if cabecera.dst_port == em[3]:
                            esta_en_tabla = True
                            fila = em
                if esta_en_tabla == False: #Si no está en la tabla
                    #Se crea un puerto aleatorio.
                    nuevo_puerto = random.randint(5000,5010)
                    while nuevo_puerto in self.used_ports:
                        nuevo_puerto = random.randint(5000,5010)
                    self.used_ports.append(nuevo_puerto)
                    #Se añade a la tabla de nat
                    self.tablaNat.append([cabecera_ip.src,cabecera.src_port,ip_publica,nuevo_puerto])
                    #Buscar la entrada aplicable en la tabla de enrutamiento
                    (next_hop, port) = self.find_in_routingTable(cabecera_ip.dst)
                    #Conozco la mac de destino?
                    if next_hop in self.ipToMac.keys():
                        mac = self.ipToMac[next_hop]
                    else:
                        #Si no está dentro de la tabla se construye un paquete ARP para averiguar su MAC
                        self.enviar_arp(mac_origen=self.portsToIps[0][2], port=port, next_hop=next_hop, datapath=datapath, msg=msg, nat=1, puertoNat=nuevo_puerto)
                else: #Si está en la tabla
                    #Se cambian las propiedades del paquete
                    #Buscar la entrada aplicable en la tabla de enrutamiento
                    (next_hop, port) = self.find_in_routingTable(cabecera_ip.dst)
                    if red_privada == False: #Proviene de la red pública
                        self.insertar_flujo(msg=msg, mod=0, puerto_destino=fila[1], ip_destino=fila[0], sentido=0, protoc=1, port=2, mac=self.ipToMac[fila[0]])
                    if red_privada == True: #Proviene de la red privada
                        #Conozco la mac de destino?
                        if next_hop in self.ipToMac.keys():
                            mac = self.ipToMac[next_hop]
                        else:
                            #Si no está dentro de la tabla se construye un paquete ARP para averiguar su MAC
                            self.enviar_arp(mac_origen=self.portsToIps[0][2], port=port, next_hop=next_hop, datapath=datapath, msg=msg, nat=1, puertoNat=fila[3])
    def insertar_flujo(self, msg, mac=None, port=1, mod=1, protoc=1, puerto_origen=None, puerto_destino=None, ip_origen=None, ip_destino=None,sentido=1):
        datapath = msg.datapath
        pckt = packet.Packet(msg.data)
        ipPacket = pckt.get_protocol(ipv4.ipv4)
        eth = pckt.get_protocol(ethernet.ethernet)
        if mod == 1: #Paquete ICMP
            match = datapath.ofproto_parser.OFPMatch(eth_dst=eth.dst, eth_type=ether.ETH_TYPE_IP)
            actions = [
                datapath.ofproto_parser.OFPActionSetField(eth_src=self.portsToIps[port-1][2]),
                datapath.ofproto_parser.OFPActionSetField(eth_dst=mac),
                datapath.ofproto_parser.OFPActionOutput(port)
                ]
        elif mod == 0: # TCP/UDP
            if sentido == 1: #Proviene de la red privada
                if protoc==1: #TCP
                    match = datapath.ofproto_parser.OFPMatch(eth_src=self.portsToIps[0][2], eth_dst=mac, eth_type=ether.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP)
                    actions = [
                        datapath.ofproto_parser.OFPActionSetField(tcp_src=puerto_origen),
                        datapath.ofproto_parser.OFPActionSetField(ipv4_src=ip_origen),
                        datapath.ofproto_parser.OFPActionSetField(eth_src=self.portsToIps[port-1][2]),
                        datapath.ofproto_parser.OFPActionSetField(eth_dst=mac),
                        datapath.ofproto_parser.OFPActionOutput(port)
                        ]
                elif protoc==0: #UPD
                    match = datapath.ofproto_parser.OFPMatch(eth_src=self.portsToIps[0][2], eth_dst=mac, eth_type=ether.ETH_TYPE_IP, ip_proto=inet.IPPROTO_UDP)
                    actions = [
                        datapath.ofproto_parser.OFPActionSetField(udp_src=puerto_origen),
                        datapath.ofproto_parser.OFPActionSetField(ipv4_src=ip_origen),
                        datapath.ofproto_parser.OFPActionSetField(eth_src=self.portsToIps[port-1][2]),
                        datapath.ofproto_parser.OFPActionSetField(eth_dst=mac),
                        datapath.ofproto_parser.OFPActionOutput(port)
                        ]
            elif sentido == 0: #Proviene de la red publica 
                if protoc==1: #TCP
                    match = datapath.ofproto_parser.OFPMatch(eth_src=self.portsToIps[1][2], eth_dst=mac, eth_type=ether.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP)
                    actions = [
                        datapath.ofproto_parser.OFPActionSetField(tcp_dst=puerto_destino),
                        datapath.ofproto_parser.OFPActionSetField(ipv4_dst=ip_destino),
                        datapath.ofproto_parser.OFPActionSetField(eth_src=self.portsToIps[port-2][2]),
                        datapath.ofproto_parser.OFPActionSetField(eth_dst=mac),                        
                        datapath.ofproto_parser.OFPActionOutput(port)
                        ]
                elif protoc==0: #UPD
                    match = datapath.ofproto_parser.OFPMatch(eth_src=self.portsToIps[1][2], eth_dst=mac, eth_type=ether.ETH_TYPE_IP, ip_proto=inet.IPPROTO_UDP)
                    actions = [
                        datapath.ofproto_parser.OFPActionSetField(udp_dst=puerto_destino),
                        datapath.ofproto_parser.OFPActionSetField(ipv4_dst=ip_destino),
                        datapath.ofproto_parser.OFPActionSetField(eth_src=self.portsToIps[port-2][2]),
                        datapath.ofproto_parser.OFPActionSetField(eth_dst=mac),                        
                        datapath.ofproto_parser.OFPActionOutput(port)
                        ]
        self.add_flow(datapath=datapath, priority=0, match=match, actions=actions, buffer_id=msg.buffer_id)
