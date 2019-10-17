@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def add_default_rule(self, event):
        self.logger.info('######adding default rule')

        msg = event.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()  # match tutte wildcards
        actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD, 0)]  # azione di FLOOD con priorità 0
        instructions = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=instructions)

        datapath.send_msg(mod)
        self.logger.info('######flow rule set')


@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
def packet_in_handler(self, event):
    self.logger.info('######packet in')

    msg = event.msg  # oggetto che contiene la struttura dati del pacchetto in ingresso
    datapath = msg.datapath  # ID dello switch da cui arriva il pacchetto
    ofpversion = datapath.ofproto  # versione di ofp usata nell'handshake (versione attesa 1.3) (dovrebbe contenere anche delle azioni tipo OFP_FLOOD)

    # debug
    if msg.reason == ofpversion.OFPR_NO_MATCH:
        reason = 'NO MATCH'
    elif msg.reason == ofpversion.OFPR_ACTION:
        reason = 'ACTION'
    elif msg.reason == ofpversion.OFPR_INVALID_TTL:
        reason = 'INVALID TTL'
    else:
        reason = 'unknown'

    self.logger.info('OFPPacketIn received: '
                     'buffer_id=%x total_len=%d reason=%s '
                     'table_id=%d cookie=%d match=%s data=%s',
                     msg.buffer_id, msg.total_len, reason,
                     msg.table_id, msg.cookie, msg.match,
                     utils.hex_array(msg.data))

    # estraggo i dati dal pacchetto in ingresso
    pacchetto = packet.Packet(msg.data)

    # estrae il frame ethernet
    ethframe = pacchetto.get_protocol(ethernet.ethernet)
    self.logger.info('eht frame: %s', ethframe)

    # estrae il frame ip se il pacchetto ethernet contiene un pacchetto ip
    if ethframe.ethertype == 0x0800:
        ipframe = pacchetto.get_protocol(ipv4.ipv4)
        self.logger.info('src: %s   dst: %s', ipframe.src, ipframe.dst)


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

# settare la matrice che contiene porte mac corrispondenti
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src
        # get the received port number from packet_in message.
        in_port = msg.match['in_port']
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        self.logger.info(self.mac_to_port)
        self.logger.info('\n\n')
# out della funzione precedente (es)
# --> switch --> 'mac' : porta

    {1: {'00:00:00:00:00:03': 3,
        '00:00:00:00:00:02': 2,
        '00:00:00:00:00:01': 1,
        '00:00:00:00:00:06': 4,
        '00:00:00:00:00:05': 4,
        '00:00:00:00:00:04': 4},
    2: {'00:00:00:00:00:03': 1,
        '00:00:00:00:00:02': 1,
        '00:00:00:00:00:01': 1,
        '00:00:00:00:00:06': 4,
        '00:00:00:00:00:05': 3,
        '00:00:00:00:00:04': 2}}

    # funzione che crea e aggiorna il dizionario mac_to_port (matrice --> [switch_id][mac_source] = porta_ingresso)
    def set_mac_to_port(self, datapath, ethframe, porta_ingresso):
        switch_id = datapath.id
        source = ethframe.src

        self.mac_to_port.setdefault(switch_id, {})
        self.mac_to_port[switch_id][source] = porta_ingresso

        self.logger.info(self.mac_to_port)
        self.logger.info('\n\n')




        if datapath.id == 1:
            if self.lista_server[0] in self.topologia[datapath.id]:
                porta_LB = self.topologia[datapath.id]['00:00:00:00:00:04'][0]
                self.logger.info(porta_LB)

    if ethframe.ethertype == 2054:  # se il pacchetto è arp
        arpframe = pacchetto.get_protocol(arp.arp)

        if arpframe.dst_ip == self.LB_ip and arpframe.opcode == 1:
            server_mac = self.round_robin()
            server_port = self.topologia[datapath.id][server_mac][0]
            server_ip = self.topologia[datapath.id][server_mac][1]

    self.get_frame(pacchetto, datapath, porta_ingresso, ethframe)
    manda il pacchetto intercettato senza modificarlo
    datapath.send_msg(msg)


self.topologia[datapath.id][ethframe.src] = [porta_ingresso, ip]












if datapath.id == 2:
    if ethframe.ethertype == 2054:  # se ho un pacchetto arp
        arpframe = pacchetto.get_protocol(arp.arp)

        if arpframe.dst_ip == self.LB_ip and arpframe.opcode == 1:
            src_mac = arpframe.src_mac  # mac di origine da usare come destinazione nella arp reply
            src_ip = arpframe.src_ip  # ip di origine da usare come destinazione nella arp reply

            server_mac = self.round_robin()
            server_port = self.topologia[datapath.id][server_mac][0]
            server_ip = self.topologia[datapath.id][server_mac][1]

            match1 = parser.OFPMatch(eth_type=2048, eth_src=src_mac, eth_dst=self.LB_mac, ipv4_src=src_ip,
                                     ipv4_dst=self.LB_ip)
            actions1 = [parser.OFPActionSetField(ipv4_dst=server_ip),
                        parser.OFPActionSetField(eth_dst=server_mac),
                        parser.OFPActionOutput(server_port)]
            self.add_flow(datapath, 3, match1, actions1)

            match2 = parser.OFPMatch(eth_type=2048, eth_src=server_mac, eth_dst=src_mac, ipv4_src=server_ip,
                                     ipv4_dst=src_ip)
            actions2 = [parser.OFPActionSetField(ipv4_src=self.LB_ip),
                        parser.OFPActionSetField(eth_src=self.LB_mac),
                        parser.OFPActionOutput(porta_ingresso)]
            self.add_flow(datapath, 3, match2, actions2)

            self.logger.info('invio ARP REPLY del LB')
            reply = packet.Packet()  # costruzione di un paccehtto vuoto
            # costrzione del frame ethernet per la reply (dst,src,ethertype)
            ethframe_reply = ethernet.ethernet(src_mac, self.LB_mac, 2054)
            # costruzione del frame arp per la reply
            arp_reply_pkt = arp.arp(1, 2054, 6, 4, 2, self.LB_mac, self.LB_ip, src_mac, src_ip)  #

            # aggiunta dei protocolli al pacchetto
            reply.add_protocol(ethframe_reply)
            reply.add_protocol(arp_reply_pkt)
            reply.serialize()
            # uscita del pacchetto preparato sulla porta di ingresso
            actions = [parser.OFPActionOutput(porta_ingresso)]
            out = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_ANY, data=reply.data,
                                      actions=actions,
                                      buffer_id=0xffffffff)
            datapath.send_msg(out)











            self.logger.info('invio ARP REPLY del LB')
            reply = packet.Packet()  # costruzione di un paccehtto vuoto
            # costrzione del frame ethernet per la reply (dst,src,ethertype)
            ethframe_reply = ethernet.ethernet(src_mac, self.LB_mac, 2054)
            # costruzione del frame arp per la reply
            arp_reply_pkt = arp.arp(1, 2054, 6, 4, 2, self.LB_mac, self.LB_ip, src_mac, src_ip)  #

            # aggiunta dei protocolli al pacchetto
            reply.add_protocol(ethframe_reply)
            reply.add_protocol(arp_reply_pkt)
            reply.serialize()
            # uscita del pacchetto preparato sulla porta di ingresso
            actions = [parser.OFPActionOutput(porta_ingresso)]
            out = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_ANY, data=reply.data,
                                      actions=actions,
                                      buffer_id=0xffffffff)
            datapath.send_msg(out)