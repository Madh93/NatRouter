# mierdiRouter
Bueno, esta práctica nos está saliendo muy mal. He estado intentando recabar información y creo que se debe a lo siguiente:
1. No hay suficiente ayuda por internet.
2. La documentación de ryu es cuanto menos asquerosa.
3. Fujita nos odia.
Debido a estas tres causas no podemos acabar esta maldición.

## MierdiChuletario

**Conectarse a la máquina virtual**

    $ ssh -X mininet@192.168.56.101

**Iniciar Mininet**

    $ sudo mn --topo single,4 --mac --controller remote --switch ovsk,protocols=OpenFlow13 -x
    
**Iniciar Ryu**

    $ ryu-manager router.py    
    
**Cambiar direcciones**

    $ h1 ifconfig eth0 192.168.1.2 netmask 255.255.255.0
    $ h1 route add default gw 192.168.1.1 
    
**Información de la direcciones**

    $ h1 route -n
    
**Netcat TCP/UDP**

    $ h1 nc h2 12345
    $ h1 nc -uv h2 12345
    