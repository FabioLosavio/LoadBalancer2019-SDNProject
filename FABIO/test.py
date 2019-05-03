from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, ipv4, arp  # permettono di analizzare i dati all'interno del pacchtto


class LoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LoadBalancer, self).__init__(*args, **kwargs)
        # strutture dati
        self.topologia = {}  # dizionario che associa l'indirizzo mac alla porta di uscita per ogni switch
        self.round_robin_counter = 0  # contatore che permette di fare round robin (counter % numero_server)
        self.LB_mac = 'AA:AA:AA:AA:AA:AA'  # mac associato al load balancer
        self.LB_ip = '10.0.2.0'  # ip associato al load balancer
        self.num_server = 3  # indica il numero di server su cui fare round robin
        self.lista_server = ['00:00:00:00:00:04', '00:00:00:00:00:05', '00:00:00:00:00:06']
        self.logger.info('######inizializzazione completata')

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, event):
        # self.logger.info('######packet in')
        msg = event.msg  # oggetto che contiene la struttura dati del pacchetto in ingresso
        datapath = msg.datapath  # ID dello switch da cui arriva il pacchetto
        porta_ingresso = msg.match['in_port']
        pacchetto = packet.Packet(msg.data)
        ofpversion = datapath.ofproto  # versione di ofp usata nell'handshake (versione attesa 1.3)
        parser = datapath.ofproto_parser

        ethframe = pacchetto.get_protocol(ethernet.ethernet)

        self.set_topologia(pacchetto, porta_ingresso, datapath)

        # self.set_mac_to_port(datapath, ethframe, porta_ingresso)
        # self.get_frame(pacchetto, datapath, porta_ingresso, ethframe)

        # manda il pacchetto intercettato senza modificarlo
        # datapath.send_msg(msg)

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

    # funzione che stampa a schermo le informazioni dei protocolli contenuti in un pacchetto
    def get_frame(self, pacchetto, datapath, porta_ingresso, ethframe):
        # self.logger.info('eht frame: %s', ethframe)

        # estraggo il fame di livello 3 trasortato
        if ethframe.ethertype == 2048:  # frame ip
            self.logger.info('IP FRAME')
            self.logger.info('switch n: %s porta ingresso: %s', datapath.id, porta_ingresso)
            ipframe = pacchetto.get_protocol(ipv4.ipv4)
            self.logger.info('src: %s   dst: %s\n\n', ipframe.src, ipframe.dst)

            return ipframe

        elif ethframe.ethertype == 2054:  # frame arp
            self.logger.info('ARP FRAME')
            arpframe = pacchetto.get_protocol(arp.arp)
            self.logger.info('switch n: %s porta ingresso: %s', datapath.id, porta_ingresso)
            self.logger.info('src: IP:%s MAC:%s  dst: IP:%s MAC:%s\n\n',
                             arpframe.src_ip, arpframe.src_mac, arpframe.dst_ip, arpframe.dst_mac)

            return arpframe

        # else:
        #      self.logger.info('pacchetto non gestito\n\n')



    def set_topologia(self, pacchetto, porta_ingresso, datapath):
        ethframe = pacchetto.get_protocol(ethernet.ethernet)

        if ethframe.ethertype == 2048:  # frame ip
            frame = pacchetto.get_protocol(ipv4.ipv4)
            ip = frame.src

        elif ethframe.ethertype == 2054:  # frame arp
            frame = pacchetto.get_protocol(arp.arp)
            ip = frame.src_ip
        else:
            ip = 'not_defined'

        self.topologia.setdefault(datapath.id, {})
        self.topologia[datapath.id][ethframe.src] = [porta_ingresso, ip]
        self.logger.info(self.topologia)
        self.logger.info('\n\n')

    def round_robin(self):
        server_scelto = self.round_robin_counter % self.num_server  # resto della divisione intera
        self.round_robin_counter = self.round_robin_counter + 1

        if self.round_robin_counter == 3000:    # serve a non avere un contatore troppo grande
            self.round_robin_counter = 0

        return self.lista_server[server_scelto]
