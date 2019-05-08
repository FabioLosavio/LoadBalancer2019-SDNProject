# Il programma esegue il load balancing su num_server i quali mac sono specificati nella lista lista_server utilizzando
# la politica di Rund Robin. La topologia da utilizzare si attiva con il comando
# sudo mn --custom /vagrant/sdn-lab/mininetTOPO.py --topo LBNet --mac --controller=remote

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

        self.host = []

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, event):
        # self.logger.info('######packet in')
        msg = event.msg  # oggetto che contiene la struttura dati del pacchetto in ingresso
        datapath = msg.datapath  # ID dello switch da cui arriva il pacchetto
        porta_ingresso = msg.match['in_port']
        pacchetto = packet.Packet(msg.data)
        ofproto = datapath.ofproto  # versione di ofp usata nell'handshake (versione attesa 1.3)
        parser = datapath.ofproto_parser

        ethframe = pacchetto.get_protocol(ethernet.ethernet)

        if ethframe.ethertype != 0x86dd:    # escludo pacchetti ipv6 di configurazione scabiati all'avvio della topologia

            if datapath.id == 2:    # se siamo nello switch 2

                if ethframe.ethertype == 2054:  # se ho un pacchetto arp
                    arpframe = pacchetto.get_protocol(arp.arp)

                    if arpframe.dst_ip == self.LB_ip and arpframe.opcode == 1:
                        src_mac = arpframe.src_mac  # mac di origine da usare come destinazione nella arp reply
                        src_ip = arpframe.src_ip  # ip di origine da usare come destinazione nella arp reply

                        server_mac = self.round_robin()
                        server_port = self.topologia[datapath.id][server_mac][0]
                        server_ip = self.topologia[datapath.id][server_mac][1]

                        self.logger.info('invio ARP REPLY del LB')
                        reply = packet.Packet()  # costruzione di un paccehtto vuoto
                        # costrzione del frame ethernet per la reply (dst,src,ethertype)
                        ethframe_reply = ethernet.ethernet(src_mac, self.LB_mac, 2054)
                        # costruzione del frame arp per la reply
                        arp_reply_pkt = arp.arp(1, 0x800, 6, 4, 2, self.LB_mac, self.LB_ip, src_mac, src_ip)  #

                        # aggiunta dei protocolli al pacchetto
                        reply.add_protocol(ethframe_reply)
                        reply.add_protocol(arp_reply_pkt)
                        reply.serialize()
                        self.logger.info(reply)
                        # uscita del pacchetto preparato sulla porta di ingresso
                        actions = [parser.OFPActionOutput(porta_ingresso)]
                        out = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_ANY, data=reply.data,
                                                  actions=actions,
                                                  buffer_id=0xffffffff)
                        datapath.send_msg(out)

                        match1 = parser.OFPMatch(eth_type=2048, eth_src=src_mac, eth_dst=self.LB_mac, ipv4_src=src_ip,
                                                 ipv4_dst=self.LB_ip)
                        actions1 = [parser.OFPActionSetField(ipv4_dst=server_ip),
                                    parser.OFPActionSetField(eth_dst=server_mac),
                                    parser.OFPActionOutput(server_port)]
                        self.add_flow(datapath, 3, match1, actions1, 120)

                        match2 = parser.OFPMatch(eth_type=2048, eth_src=server_mac, eth_dst=src_mac, ipv4_src=server_ip,
                                                 ipv4_dst=src_ip)
                        actions2 = [parser.OFPActionSetField(ipv4_src=self.LB_ip),
                                    parser.OFPActionSetField(eth_src=self.LB_mac),
                                    parser.OFPActionOutput(porta_ingresso)]
                        self.add_flow(datapath, 3, match2, actions2, 120)

            # self.get_frame(pacchetto, datapath, porta_ingresso, ethframe)
            self.set_topologia(pacchetto, porta_ingresso, datapath)

            if ethframe.ethertype != 34525 and ethframe.dst in self.topologia[datapath.id]:
                porta_uscita = self.topologia[datapath.id][ethframe.dst][0]
            else:
                porta_uscita = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(porta_uscita)]

            if porta_uscita != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(eth_dst=ethframe.dst)
                self.add_flow(datapath, 2, match, actions, 0)

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=porta_ingresso,
                                      actions=actions, data=msg.data)
            datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.logger.info('######switch features handler')
        msg = ev.msg
        datapath = msg.datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # match: ANY, actions: out al controllore e FLOOD del pacchetto
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]

        # chiamata alla funzione add_flow che crea una flow rule con i parametri inseriti
        self.add_flow(datapath, 1, match, actions, 0)

        if datapath.id == 1:
            match = parser.OFPMatch(eth_type=2048, ipv4_dst='10.0.2.0')
            actions = [parser.OFPActionOutput(4)]
            self.add_flow(datapath, 2, match, actions, 0)

    # funzione che crea una flow rule nel controllore con i parametri indicati nella chiamata
    def add_flow(self, datapath, priority, match, actions, idle_timeout):
        self.logger.info('######add flow')
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # creazione della lista di istruzioni da eseguire
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        # creazione del messaggio da mandare in out
        out = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, idle_timeout=idle_timeout)
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
            ip = None

        self.topologia.setdefault(datapath.id, {})
        self.topologia[datapath.id][ethframe.src] = [porta_ingresso, ip]

        # self.logger.info(self.topologia)
        # self.logger.info('\n\n')

    def round_robin(self):
        server_scelto = self.round_robin_counter % self.num_server  # resto della divisione intera
        self.round_robin_counter = self.round_robin_counter + 1

        if self.round_robin_counter == 3000:  # serve a non avere un contatore troppo grande
            self.round_robin_counter = 0

        return self.lista_server[server_scelto]
