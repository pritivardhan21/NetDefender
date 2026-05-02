from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
# ADDED ipv4 and ether_types for packet inspection
from ryu.lib.packet import packet, ethernet, ipv4, ether_types 
import time # ADDED to calculate packets-per-second

class NetDefenderTarpit(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NetDefenderTarpit, self).__init__(*args, **kwargs)
        # This is the brain's memory! It remembers MAC addresses and ports.
        self.mac_to_port = {}
        
        # --- NEW: THREAT SCORING MEMORY ---
        self.ip_tracker = {}
        self.PPS_LIMIT = 50 # Flag an IP if it sends more than 50 packets per second

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info("Switch connected. Installing Table-Miss default rule.")
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Crack open the packet to look at the MAC addresses
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        # Ignore LLDP packets (controller background noise)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # --- NEW: THREAT SCORING LOGIC ---
        # Only analyze IPv4 traffic to calculate the threat score
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            src_ip = ip_pkt.src
            current_time = time.time()

            if src_ip not in self.ip_tracker:
                self.ip_tracker[src_ip] = {'count': 1, 'start_time': current_time}
            else:
                time_diff = current_time - self.ip_tracker[src_ip]['start_time']
                self.ip_tracker[src_ip]['count'] += 1

                # Evaluate the score every 1 second
                if time_diff >= 1.0:
                    pps = self.ip_tracker[src_ip]['count'] / time_diff
                    if pps > self.PPS_LIMIT:
                        self.logger.warning(f"[THREAT DETECTED] High PPS from {src_ip}: {pps:.2f} pkts/sec! Flagging for Tarpit.")
                    
                    # Reset the counter for the next 1-second window
                    self.ip_tracker[src_ip] = {'count': 1, 'start_time': current_time}
        # ---------------------------------

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        
        # 1. Learn the sender's MAC address and port
        self.mac_to_port[dpid][src] = in_port

        # 2. Decide where to send the packet
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD # If we don't know, shout it to everyone (ARP)

        actions = [parser.OFPActionOutput(out_port)]

        # 3. If we know where it goes, install a rule in the switch so it doesn't bother the controller next time!
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        # 4. Send the actual packet on its way
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
