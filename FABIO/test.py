from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, ipv4, arp  # permettono di analizzari i dati all'interno del pacchtto
from ryu.topology.api import get_all_link, get_all_host, get_all_switch, get_host


class LoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LoadBalancer, self).__init__(*args, **kwargs)
        self.MACList = []
        self.IPList = []
        self.logger.info('######inizializzazione completata')

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, event):
        self.logger.info('######packet in')
        msg = event.msg  # oggetto che contiene la struttura dati del pacchetto in ingresso
        datapath = msg.datapath  # ID dello switch da cui arriva il pacchetto
        ofpversion = datapath.ofproto  # versione di ofp usata nell'handshake (versione attesa 1.3)
        parser = datapath.ofproto_parser
        # estraggo i dati dal pacchetto in ingresso
        pacchetto = packet.Packet(msg.data)

        porta_ingresso = msg.match['in_port']

        # estrae il frame ethernet
        ethframe = pacchetto.get_protocol(ethernet.ethernet)
        # escludo i pacchetti ipv6 di sincronizzazione trasmessi al setup della rete
        if ethframe.ethertype != 34525:
            self.logger.info('eht frame: %s', ethframe)
            if ethframe.ethertype == 2048:
                self.logger.info('IP FRAME')
                self.logger.info('switch n: %s porta ingresso: %s', datapath.id, porta_ingresso)
                ipframe = pacchetto.get_protocol(ipv4.ipv4)
                self.logger.info('src: %s   dst: %s\n\n', ipframe.src, ipframe.dst)
            elif ethframe.ethertype == 2054:
                self.logger.info('ARP FRAME')
                arpframe = pacchetto.get_protocol(arp.arp)
                self.logger.info('switch n: %s porta ingresso: %s', datapath.id, porta_ingresso)
                self.logger.info('src: IP:%s MAC:%s  dst: IP:%s MAC:%s\n\n',
                                 arpframe.src_ip, arpframe.src_mac, arpframe.dst_ip, arpframe.dst_mac)
            else:
                self.logger.info('pacchetto non gestito\n\n')
        # manda il pacchetto intercettato senza modificarlo
        datapath.send_msg(msg)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.logger.info('######switch features handler')
        datapath = ev.msg.datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # match: ANY, actions: out al controllore e FLOOD del pacchetto
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER),
                   parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        # chiamata alla funzione add_flow che crea una flow rule con i parametri inseriti
        self.add_flow(datapath, 0, match, actions)

    # funzione che crea una flow rule nel controllore con i parametri indicati nella chiamata
    def add_flow(self, datapath, priority, match, actions):
        self.logger.info('######add flow')
        ofproto = datapath.ofproto

        parser = datapath.ofproto_parser
        # creazione della lista di istruzioni da eseguire
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        # creazione del messaggio da mandare in out
        out = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(out)
