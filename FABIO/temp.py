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













if datapath.id == 1 and ipframe.dst == '10.0.2.0' :
    actions = [parser.OFPActionOutput(4)]
    match = parser.OFPMatch(ipv4_dst='10.0.2.0')
    add