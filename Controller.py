from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ipv4
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu import utils

class IPPort():
    def __init__(self, IP, PORT):
        IP_input = IP
        Port_input = PORT

class LoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # inizializzazione della classe
    def __init__(self, *args, **kwargs):
        super(LoadBalancer, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # lista - tabella IP
        self.ip_port_list = []

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # lettura delle informazioni dal pacchetto in ingresso
        messaggio = ev.msg
        datapath = messaggio.datapath
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        input_port_temp = messaggio.match['in_port']

        pkt = packet.Packet(data=messaggio.data)
        pkt_ip = pkt.get_protocol(ipv4.ipv4)

        if pkt_ip is not None :
            input_ip_temp = pkt_ip.src;

            pkt_ethernet = pkt.get_protocol(ethernet.ethernet)

            found = False

            for i in len(self.ip_port_list) :
                if input_ip_temp == self.ip_port_list[i].IP_input :
                    self.ip_port_list[i].Port_input = input_port_temp
                    found = True
            if found == False :
                self.ip_port_list.append(IPPort(input_ip_temp, input_port_temp))

            for i in len(self.ip_port_list):
                self.logger.info("IP: %s, Port: %d\n", self.ip_port_list[i].IP_input, self.ip_port_list[i].Port_input)

            self.logger.info("\n\n")
        else :
            pkt_ip.dst = '11.0.0.255'

        pkt_ip.csum = 0
        pkt.serialize()