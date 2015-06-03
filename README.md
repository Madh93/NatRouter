# NatRouter

Práctica de Laboratorio de Redes sobre la implementación del servicio PAT sobre un Router simple.

## Comandos útiles para la implementación

**Conectarse a la máquina virtual**

    $ ssh -X mininet@192.168.56.101

**Iniciar Mininet**

    $ sudo mn --topo single,4 --mac --controller remote --switch ovsk,protocols=OpenFlow13 -x

**Cargar configuración**

    $ source router4.conf   
    
**Iniciar Ryu**

    $ ryu-manager router.py    
    
**Cambiar direcciones**

    $ h1 ifconfig eth0 192.168.1.2 netmask 255.255.255.0
    $ h1 route add default gw 192.168.1.1 
    
**Información de la direcciones**

    $ h1 route -n
    
**Netcat TCP/UDP**

    $ h1 nc -p 346 h2 12345
    $ h1 nc -uvp 236 h2 12345
    