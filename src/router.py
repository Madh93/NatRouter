#!/usr/bin/python
#coding=utf-8

# Ŕyu
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
  set_ev_cls,
  # CONFIG_DISPATCHER,    # PROVISIONAL
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

# ###### PROVISIONALES... probablente se quede ######
from ryu.lib import hub

# Netaddr
from netaddr.ip import (
  IPAddress,
  IPNetwork
)

# Otros
import random

# Funcionalidades
import Arp
import Icmp

#def check_icmp




class Router(app_manager.RyuApp):

    # mac_to_port=dict()
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    IP_PUBLICA = '10.0.0.69'

    def __init__(self, *args, **kwargs):
        super(Router, self).__init__(*args, **kwargs)
        self.ping_q = hub.Queue()
        # self.portInfo = {}
        # self.arpInfo = {}
        # self.routingInfo = {}
        # self.mplsInfo = {}

        # self.mac_to_port=dict() # ELIMINAR

        ###### dict() mas ineficiente que {}!!!
        self.ipToMac = dict()
        
        self.ports_to_ips = [('10.0.0.69','255.255.255.0','00:00:00:00:00:50'),
                             ('10.0.1.1','255.255.255.0','00:00:00:00:00:60')]

        self.tablaEnrutamiento = [('10.0.0.0','255.255.255.0',1,None),
                                  ('10.0.1.0','255.255.255.0',2,None)]

        #[ip_privada(src), puerto_privado(src_port), ip_publica(dst), puerto_publico(dst_port), mac_origen]
        self.tablaNat = []

        self.portsPool = Range(5000,5010)

        self.dict_pendientes = dict()


    #---------------------------------------------#
    # Gestión de los paquetes entrantes al Router #
    #---------------------------------------------#
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev): 

        msg = ev.msg 
        datapath = msg.datapath
        # ofproto = datapath.ofproto
        in_port = msg.match['in_port']        

        packet = Packet(msg.data)
        eth = packet.get_protocol(ethernet.ethernet)
        # ethertype = packet.get_protocol(ethernet.ethernet)
        # src = eth.src
        # dst = eth.dst

        # self.mac_to_port[src] = in_port
        # used_ports = [] # USO LIMITADO...

        if eth.ethertype == ether.ETH_TYPE_ARP: #Si se trata de un paquete ARP
            self.receive_arp(datapath=datapath, packet=packet, etherFrame=eth, inPort=in_port)

        elif eth.ethertype == ether.ETH_TYPE_IP: #Si se trata de un paquete IP

            if packet.get_protocol(tcp.tcp):    #Paquete TCP
                self.receive_transport(datapath=datapath, packet=packet, proto=packet.get_protocol(tcp.tcp), type="TCP")

            elif packet.get_protocol(udp.udp):  #Paquete UDP
                self.receive_transport(datapath=datapath, packet=packet, proto=packet.get_protocol(udp.udp), type="UDP")
            
            else:    #Se trata de un paquete ICMP
                self.receive_ip(datapath=datapath, packet=packet, etherFrame=eth, inPort=in_port, msg=msg)


            # # print "PAQUETE AL LLEGAR: ", packet
            # trama_ip = packet.get_protocol(ipv4.ipv4)
            # try: #Intenta almacenar un paquete del tipo TCP
            #     tcp_port = packet.get_protocol(tcp.tcp)
            # except:
            #     pass
            # try: #Intenta almacenar un paquete del tipo UDP
            #     udp_port = packet.get_protocol(udp.udp)
            # except:
            #     pass
            # if tcp_port: #Se trata de un paquete TCP
            #     #ALMACENAR LA INFORMACIÓN EN LA TABLA:
            #     esta_en_tabla = False
            #     fila = None
            #     red_privada = True
            #     if in_port in [2,3,4]: #Si pertenece a la red privada
            #         for em in self.tablaNat: #Busca en la tabla por Ip origen ??
            #             if trama_ip.src == em[0]:
            #                 esta_en_tabla = True
            #                 fila = em
            #     else: #Si pertenece a la red pública
            #         red_privada = False
            #         for em in self.tablaNat: #Busca en la tabla por puerto destino ??
            #             if tcp_port.dst_port == em[3]:
            #                 esta_en_tabla = True
            #                 fila = em

            #     if esta_en_tabla == False: #Si no está en la tabla
            #         #Se crea un puerto aleatorio.
            #         nuevo_puerto = random.randint(5000,5010)
            #         while nuevo_puerto in used_ports:
            #             nuevo_puerto = random.randint(5000,5010)
            #         print "PUERTO A INSERTAR: ", nuevo_puerto
            #         used_ports.append(nuevo_puerto)
            #         #Se añade a la tabla de nat
            #         self.tablaNat.append([trama_ip.src,tcp_port.src_port,ip_publica,nuevo_puerto,src])
            #         #Se cambian las propiedades del paquete


            #         #AQUÍ SE METE ARP:


            #         self.insertar_flujo(msg=msg, mod=0, puerto_origen=nuevo_puerto, ip_origen=ip_publica, sentido=1, protoc=1, port=0) #Pasarle una MAC

            #     else: #Si está en la tabla
            #         #Se cambian las propiedades del paquete
            #         if red_privada == False: #Proviene de la red pública
            #             self.insertar_flujo(msg=msg, mod=0, puerto_destino=fila[1], ip_destino=fila[0], sentido=0, protoc=1, port=0, mac=fila[4])
            #         if red_privada == True: #Proviene de la red privada


            #             #AQUÍ SE METE ARP:


            #             self.insertar_flujo(msg=msg, mod=0, puerto_origen=fila[3], ip_origen=ip_publica, sentido=1, protoc=1, port=0) #Pasarle una MAC
            # elif udp_port: #Se trata de un paquete UDP
            #     #ALMACENAR LA INFORMACIÓN EN LA TABLA:
            #     esta_en_tabla = False
            #     fila = None
            #     red_privada = True
            #     if in_port in [2,3,4]: #Si pertenece a la red privada
            #         for em in self.tablaNat: #Busca en la tabla 
            #             if trama_ip.src == em[0]:
            #                 esta_en_tabla = True
            #                 fila = em
            #     else: #Si pertenece a la red pública
            #         red_privada = False
            #         for em in self.tablaNat: #Busca en la tabla 
            #             if udp_port.dst_port == em[3]:
            #                 esta_en_tabla = True
            #                 fila = em

            #     if esta_en_tabla == False: #Si no está en la tabla
            #         #Se añade a la tabla de nat

            #         nuevo_puerto = random.randint(5000,5010)
            #         while nuevo_puerto in used_ports:
            #             nuevo_puerto = random.randint(5000,5010)
            #         print "PUERTO A INSERTAR: ", nuevo_puerto
            #         used_ports.append(nuevo_puerto)

            #         self.tablaNat.append([trama_ip.src,udp_port.src_port,ip_publica,nuevo_puerto,src])

            #         (next_hop, port) = self.find_in_routingTable(ipPacket.dst) #Almacena el puerto y el siguiente salto
                    

            #         #AQUÍ SE METEN COSAS:


            #         self.insertar_flujo(msg=msg, mod=0, puerto_origen=nuevo_puerto, ip_origen=ip_publica, sentido=1, protoc=0, port=0) #Pasarle una MAC

            #     else: #Si está en la tabla
            #         #Se cambian las propiedades del paquete
            #         if red_privada == False: #Proviene de la red pública
            #             self.insertar_flujo(msg=msg, mod=0, puerto_destino=fila[1], ip_destino=fila[0], sentido=0, protoc=0, port=0, mac=fila[4]) #Pasarle una MAC
            #         if red_privada == True: #Proviene de la red privada
                    

            #             #AQUÍ SE METE ARP:


            #             self.insertar_flujo(msg=msg, mod=0, puerto_origen=fila[3], ip_origen=ip_publica, sentido=1, protoc=0, port=0) 
            # else: #Se trata de un paquete ICMP
            #     self.receive_ip(datapath, packet, ethertype, in_port, msg)
            # print "TABLA: ", self.tablaNat
            # print "PUERTO DE ENTRADA: ", in_port


    #----------------------------------------------------------#
    # Procesar si se trata de una respuesta o una peticion ARP #
    #----------------------------------------------------------#
    def receive_arp(self, datapath, packet, etherFrame, inPort):

        arp_msg = packet.get_protocol(arp.arp)

        if arp_msg.opcode == arp.ARP_REQUEST:
            if arp_msg.dst_ip == self.ports_to_ips[inPort-1][0]:
                # e = ethernet.ethernet(dst=etherFrame.src,
                #                         src=self.ports_to_ips[inPort-1][2],
                #                         ethertype=ether.ETH_TYPE_ARP)
                # a = arp.arp(opcode=arp.ARP_REPLY,
                #             src_mac=self.ports_to_ips[inPort-1][2],
                #             src_ip=arp_msg.dst_ip,
                #             dst_mac=etherFrame.src,
                #             dst_ip=arp_msg.src_ip)
                # puerto=inPort
                # p = Packet()
                # p.add_protocol(e)
                # p.add_protocol(a)

                arp_pkt = Arp.build_packet(proto=arp_msg, 
                                           etherFrame=etherFrame, 
                                           srcMac=self.ports_to_ips[inPort-1][2])

                # self.send_packet(datapath, puerto, p)
                self.send_packet(datapath, inPort, arp_pkt)
        
        elif arp_msg.opcode == arp.ARP_REPLY:
            self.ipToMac[arp_msg.src_ip] = arp_msg.src_mac
            for (msg,port) in self.dict_pendientes[arp_msg.src_ip]:
                self.insertar_flujo(msg=msg, mac=arp_msg.src_mac, port=port, mod=1)
            self.dict_pendientes[arp_msg.src_ip] = []

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


    #---------------------------------------------------#
    # Función que se usa cuando se recibe un paquete IP #
    #---------------------------------------------------#
    def receive_ip(self, datapath, packet, etherFrame, inPort, msg):

        ipPacket = packet.get_protocol(ipv4.ipv4)

        #Si va destinado al router
        if ipPacket.dst == self.ports_to_ips[0][0]:
            if ipPacket.proto == inet.IPPROTO_ICMP:
                icmpPacket = packet.get_protocol(icmp.icmp)
                self.check_icmp(datapath, etherFrame, ipPacket, icmpPacket, inPort) #Se usa una función que trata un paquete ICMP 
                # return 0
            else:
                send_packet(datapath=datapath,port=inPort,packet=packet) #Se envía el paquete
                # return 1
        #Si no va destinado al router
        else:
            (next_hop, port) = self.find_in_routingTable(ipPacket.dst) #Almacena el puerto y el siguiente salto
            #en port y en next_hop
            if next_hop in self.ipToMac.keys(): #Si está dentro de la tabla de ips y macs se envía.
                match = datapath.ofproto_parser.OFPMatch(eth_dst=self.ipToMac[next_hop]) 
                actions = [datapath.ofproto_parser.OFPActionOutput(port)]

                #self.add_flow(datapath, 0, match, actions)
                self.insertar_flujo(msg=msg, mac=self.ipToMac[next_hop], port=port, mod=1)
            else: #Si no está dentro de la tabla se construye un paquete ARP para averiguar su MAC
                # print "---- NEXT_HOP -----", next_hop
                # e = ethernet.ethernet(src=etherFrame.dst, ethertype=ether.ETH_TYPE_ARP)
                # a = arp.arp(opcode=arp.ARP_REQUEST,
                #             src_ip=self.ports_to_ips[port-1][0],
                #             src_mac=etherFrame.src,
                #             dst_ip=next_hop)
                # puerto = etherFrame.src
                # p = Packet()
                # p.add_protocol(e)
                # p.add_protocol(a)

                p = Arp.build_packet(srcIp=self.ports_to_ips[port-1][0], dstIp=next_hop)

                if next_hop not in self.dict_pendientes:
                    self.dict_pendientes[next_hop] = []
                self.dict_pendientes[next_hop] = self.dict_pendientes[next_hop] + [(msg, port)]
                self.send_packet(datapath=datapath, port=port, packet=p)

            #find_mac(self, datapath, etherFrame, msg)        


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
        # e = ethernet.ethernet(dstMac, srcMac, ether.ETH_TYPE_IP) #Construye el protocolo ethernet
        # iph = ipv4.ipv4(4, 5, 0, 0, 0, 2, 0, ttl, 1, 0, srcIp, dstIp) #Construye la parte del protocolo IP
        # echo = icmp.echo(id, seq, data) #Construye la parte del echo que se añadirá al protocolo icmp
        # icmph = icmp.icmp(type, 0, 0, echo) #Construye la parte del icmp

        # p = Packet() #Crea el paquete
        # p.add_protocol(e) #Añade el protocolo ethernet
        # p.add_protocol(iph) #Añade el protocolo ip
        # p.add_protocol(icmph) #Añade el protocolo icmp
        # p.serialize() #Serializa todo

        p = Icmp.build_packet(srcMac=srcMac, srcIp=srcIp, dstMac=dstMac, dstIp=dstIp, seq=seq, data=data, id=id, type=type, ttl=ttl)

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)] #Enviar por el puerto outPort
        #Mensaje a enviar
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=p.data)
        datapath.send_msg(out) #Enviar mensaje            