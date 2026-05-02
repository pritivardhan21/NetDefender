# =============================================================================
#  NetDefender: AI-Driven SDN Defense & Redirection
#  Version 2.6 — Deterministic attacker-first processing (race condition fix)
#
#  Author   : Pritivardhan (TEEP/FTIP Internship — Prof. Ming-Shen Jian)
#  Strategy : Pure behavioral heuristics via Z-Score anomaly detection
#             and Connection Diversity Ratio (CDR). No ML models. No .pkl.
#             No pre-trained signatures. Zero-day detection by math alone.
#
#  Detection Vectors:
#    [1] Z-Score Flood Detection  → ICMP Floods, TCP SYN Floods, UDP Floods
#    [2] CDR Slow-Attack Detection → Slowloris, low-and-slow connection abuse
#
#  Mitigation:
#    - Hardware-level DROP rule pushed to OVS at priority 100
#    - Automatic rehabilitation after configurable block duration
#    - Blocked hosts get a fresh baseline on re-admission
# =============================================================================

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp
from ryu.lib import hub
import math
import time


# =============================================================================
#  TUNABLE THRESHOLDS — Adjust without touching core logic
# =============================================================================

MONITOR_INTERVAL     = 3      # Heartbeat: seconds between stat polls
HISTORY_WINDOW       = 10     # Rolling window size (number of PPS samples)
MIN_HISTORY_POINTS   = 3      # Minimum samples before Z-Score is computed
Z_SCORE_THRESHOLD    = 3.0    # Z-Score above this = statistical anomaly
MIN_PPS_THRESHOLD    = 20     # Ignore low-volume noise below this PPS
BLOCK_DURATION       = 30     # Seconds before a blocked host is re-evaluated
FLOW_IDLE_TIMEOUT    = 30     # Seconds of inactivity before forwarding flow expires
CDR_MAX_TARGETS      = 5      # Max unique destinations before CDR alert
CDR_MAX_PPS          = 15     # CDR alert only fires when PPS is LOW (Slowloris)
CLEANUP_INTERVAL         = 60  # Seconds between stale-state cleanup cycles
VICTIM_COOLDOWN_DURATION = 12  # Seconds a guarded victim MAC is immune (covers ~4 polls)


class NetDefenderLiveAI(app_manager.RyuApp):
    """
    NetDefender Ryu Controller Application.

    Implements a custom "Trust Engine" that monitors all active flows
    using two complementary behavioral heuristics:

      1. Z-Score Anomaly Detection:
         Maintains a rolling PPS history per source MAC. Computes the
         statistical Z-Score of current traffic against the historical
         baseline. A spike beyond Z_SCORE_THRESHOLD with sufficient
         volume triggers an immediate hardware DROP.

      2. Connection Diversity Ratio (CDR):
         Tracks the number of unique destinations contacted by each
         source. A host with many targets but very low PPS matches the
         Slowloris/low-and-slow attack profile and is flagged separately.

    No ML models, no .pkl files, no pre-trained signatures.
    Detection is driven entirely by runtime behavioral mathematics.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # -------------------------------------------------------------------------
    #  INITIALISATION
    # -------------------------------------------------------------------------

    def __init__(self, *args, **kwargs):
        super(NetDefenderLiveAI, self).__init__(*args, **kwargs)

        # --- Switch & Forwarding State ---
        self.mac_to_port  = {}   # {dpid: {mac: port}}
        self.datapaths    = {}   # {dpid: datapath}  — registered switches

        # --- Trust Engine Memory ---
        self.host_history    = {}  # {src_mac: [pps_1, pps_2, ...]}  rolling window
        self.last_pkt_count  = {}  # {src_mac: total_packet_count}    delta tracking
        self.blocked_macs    = {}  # {src_mac: block_timestamp}       penalty box
        self.src_dst_map     = {}  # {src_mac: set(dst_macs)}         CDR tracking
        self.victim_cooldown = {}  # {src_mac: timestamp} — guarded victims immune for N secs
        self.known_victims   = set()  # permanent record of MACs ever identified as victims

        self._print_banner()

        # Spawn background threads
        self.monitor_thread = hub.spawn(self._monitor)
        self.cleanup_thread = hub.spawn(self._cleanup_loop)

    def _print_banner(self):
        self.logger.info("=" * 65)
        self.logger.info("  NetDefender v2.6  |  Trust Engine + CDR Active")
        self.logger.info("  Detection : Z-Score Flood + Slowloris CDR Heuristic")
        self.logger.info("  Fix 2.6   : Deterministic attacker-first batch processing")
        self.logger.info("  Strategy  : Pure behavioral math — no ML models")
        self.logger.info("=" * 65)

    # =========================================================================
    #  OPENFLOW EVENT HANDLERS
    # =========================================================================

    # -------------------------------------------------------------------------
    #  Switch Handshake — install table-miss flow
    # -------------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath
        self.logger.info(f"[SWITCH] Registered datapath {datapath.id}")

        # Table-miss: send all unmatched packets to controller
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions)

    # -------------------------------------------------------------------------
    #  Packet-In — forwarding logic + CDR tracking
    # -------------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        in_port  = msg.match['in_port']
        pkt      = packet.Packet(msg.data)
        eth      = pkt.get_protocols(ethernet.ethernet)[0]

        # --- CDR: Record unique destination contacts per source ---
        self.src_dst_map.setdefault(eth.src, set()).add(eth.dst)

        # ARP — always forward normally, no Trust Engine analysis needed
        if eth.ethertype == 0x0806:
            self._standard_forwarding(msg, eth, in_port)
            return

        # IPv4 only — drop non-IP non-ARP traffic silently
        if not pkt.get_protocol(ipv4.ipv4):
            return

        # Block packets at the controller level if already in penalty box
        if eth.src in self.blocked_macs:
            remaining = BLOCK_DURATION - (time.time() - self.blocked_macs[eth.src])
            if remaining > 0:
                self.logger.debug(
                    f"[BLOCKED] Packet from {eth.src} suppressed "
                    f"({remaining:.0f}s remaining in penalty box)"
                )
                return
            # Block expired — allow through, rehabilitation handled in Trust Engine

        self._standard_forwarding(msg, eth, in_port)

    # =========================================================================
    #  FORWARDING HELPERS
    # =========================================================================

    def _standard_forwarding(self, msg, eth, in_port):
        """
        Standard MAC-learning forwarding. Installs a low-priority
        (priority=1) forwarding flow with an idle timeout so stale
        flows self-expire and don't bloat the OVS table.
        """
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        dst      = eth.dst
        src      = eth.src
        dpid     = format(datapath.id, "d").zfill(16)

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self._add_flow(
                datapath, priority=1, match=match, actions=actions,
                buffer_id=msg.buffer_id, idle_timeout=FLOW_IDLE_TIMEOUT
            )
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                return

        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        out  = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data
        )
        datapath.send_msg(out)

    def _add_flow(self, datapath, priority, match, actions,
                  buffer_id=None, idle_timeout=0, hard_timeout=0):
        """
        Generic helper to install an OpenFlow flow rule.
        Pass idle_timeout / hard_timeout for auto-expiring flows.
        Pass actions=[] to install a DROP rule.
        """
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst    = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod     = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            buffer_id=buffer_id if buffer_id else ofproto.OFP_NO_BUFFER
        )
        datapath.send_msg(mod)

    def _install_drop(self, datapath, src_mac):
        """
        Push a high-priority hardware DROP rule for the attacker's MAC.
        Hard timeout = BLOCK_DURATION so OVS self-cleans the rule
        when the controller's penalty box expires.
        """
        parser = datapath.ofproto_parser
        match  = parser.OFPMatch(eth_src=src_mac)
        self._add_flow(
            datapath, priority=100, match=match, actions=[],
            hard_timeout=BLOCK_DURATION
        )
        self.blocked_macs[src_mac] = time.time()
        # Reset packet counter so rehab PPS probe starts clean (no negative delta)
        self.last_pkt_count.pop(src_mac, None)
        self.logger.warning(
            f"[DROP INSTALLED] {src_mac} — hardware DROP active for "
            f"{BLOCK_DURATION}s"
        )

    # =========================================================================
    #  TRUST ENGINE HEARTBEAT
    # =========================================================================

    def _monitor(self):
        """Background thread: request flow stats from every switch every N seconds."""
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(MONITOR_INTERVAL)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req    = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # =========================================================================
    #  Z-SCORE MATHEMATICS — The Brain of NetDefender
    # =========================================================================

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
        Processes per-flow statistics and runs both heuristics:
          [1] Z-Score Anomaly Detection (flood attacks)
          [2] CDR Heuristic            (Slowloris / low-and-slow)
        """
        body     = ev.msg.body
        datapath = ev.msg.datapath
        parser   = datapath.ofproto_parser

        # ------------------------------------------------------------------
        #  PASS 1: Compute PPS for all active, unblocked MACs in this batch.
        #  Store results so Pass 2 can make decisions with full batch context.
        #  This is the core fix for the victim-MAC false-positive problem:
        #  by seeing all PPS values before acting, we can identify the single
        #  highest-PPS offender and ignore symmetric reply traffic from victims.
        # ------------------------------------------------------------------
        batch = {}   # {src_mac: current_pps}

        for stat in body:
            if 'eth_src' not in stat.match:
                continue
            src_mac = stat.match['eth_src']

            # Skip hosts still actively blocked
            if src_mac in self.blocked_macs:
                if time.time() - self.blocked_macs[src_mac] < BLOCK_DURATION:
                    continue

            # Skip hosts in victim cooldown — they're protected, not blocked
            if src_mac in self.victim_cooldown:
                if time.time() - self.victim_cooldown[src_mac] < VICTIM_COOLDOWN_DURATION:
                    self.logger.info(
                        f"[VICTIM COOLDOWN] {src_mac} — immune, skipping this poll."
                    )
                    # Still update last_pkt_count so delta is fresh when cooldown ends
                    self.last_pkt_count[src_mac] = stat.packet_count
                    continue
                else:
                    # Cooldown expired — delete key, reset history for fresh baseline
                    del self.victim_cooldown[src_mac]
                    self.host_history[src_mac] = []
                    self.logger.info(f"[VICTIM COOLDOWN EXPIRED] {src_mac} — resuming monitoring.")

            current_total              = stat.packet_count
            last_total                 = self.last_pkt_count.get(src_mac, 0)
            pps                        = (current_total - last_total) / float(MONITOR_INTERVAL)
            # Fix 2: Always reset last_pkt_count so rehab probe starts clean
            self.last_pkt_count[src_mac] = current_total

            if pps > 0:
                batch[src_mac] = pps

        # ------------------------------------------------------------------
        #  PASS 2: Rehabilitation checks on expired blocks (not in batch yet).
        #  Reset last_pkt_count on block installation (fix for negative PPS).
        # ------------------------------------------------------------------
        for src_mac in list(self.blocked_macs.keys()):
            elapsed = time.time() - self.blocked_macs[src_mac]
            if elapsed < BLOCK_DURATION:
                continue

            # Block has expired — use the PPS already computed in Pass 1
            probe_pps = batch.get(src_mac, 0)

            if probe_pps > MIN_PPS_THRESHOLD:
                # Traffic still elevated — extend block, remove from batch
                self.blocked_macs[src_mac] = time.time()
                batch.pop(src_mac, None)
                self.logger.warning(
                    f"[REHAB DENIED] {src_mac} | PPS still high: "
                    f"{probe_pps:.2f} | Block extended {BLOCK_DURATION}s."
                )
            else:
                # Calm — re-admit with clean slate
                del self.blocked_macs[src_mac]
                self.host_history[src_mac] = []
                self.src_dst_map[src_mac]  = set()
                batch.pop(src_mac, None)   # Skip this cycle; build baseline next poll
                self.logger.info(
                    f"[REHAB GRANTED] {src_mac} re-admitted after {elapsed:.0f}s. "
                    f"PPS: {probe_pps:.2f}. Fresh baseline starts next poll."
                )

        # ------------------------------------------------------------------
        #  PASS 3: Run heuristics on clean batch.
        #  Victim MAC protection: if multiple MACs spike simultaneously to
        #  the SAME high PPS (bidirectional flood pattern), only block the
        #  one whose Z-Score fired first — skip all others that cycle.
        # ------------------------------------------------------------------
        blocked_this_cycle = set()

        for src_mac, current_pps in sorted(batch.items(), key=lambda x: x[1], reverse=True):

            if src_mac in blocked_this_cycle:
                continue

            # ---- CDR Heuristic: Slowloris / Low-and-Slow ----
            dst_count = len(self.src_dst_map.get(src_mac, set()))
            if dst_count > CDR_MAX_TARGETS and current_pps < CDR_MAX_PPS:
                self.logger.warning(
                    f"[SLOWLORIS SIGNATURE] {src_mac} | "
                    f"Unique targets: {dst_count} | PPS: {current_pps:.2f} | "
                    f"Low-and-slow profile detected. DROPPING."
                )
                self._install_drop(datapath, src_mac)
                blocked_this_cycle.add(src_mac)
                continue

            # ---- Z-Score Heuristic: Flood Detection ----
            history = self.host_history.setdefault(src_mac, [])

            # Reject poisoned baseline samples during an active flood.
            # If a baseline sample is high-volume, the flood is still ongoing.
            # If this host was recently a guarded victim, apply a secondary
            # cooldown instead of an outright attacker-style block — it's
            # almost certainly still receiving reply traffic, not attacking.
            if len(history) < MIN_HISTORY_POINTS:
                # Choose poison threshold based on victim history:
                # Known victims use a tighter threshold (2× normal) since their
                # legitimate baseline is ~1 PPS. Unknown hosts use 10× threshold.
                poison_threshold = (MIN_PPS_THRESHOLD * 2 if src_mac in self.known_victims
                                    else MIN_PPS_THRESHOLD * 10)
                if current_pps > poison_threshold:
                    recently_guarded = src_mac in self.known_victims
                    if recently_guarded:
                        # Victim still seeing flood reply traffic — extend cooldown
                        self.victim_cooldown[src_mac] = time.time()
                        self.last_pkt_count.pop(src_mac, None)
                        self.host_history[src_mac] = []
                        blocked_this_cycle.add(src_mac)
                        self.logger.info(
                            f"[VICTIM RE-SHIELD] {src_mac} | PPS: {current_pps:.2f} | "
                            f"Flood still active — cooldown extended {VICTIM_COOLDOWN_DURATION}s."
                        )
                    else:
                        # Unknown host with high baseline sample — likely attacker
                        self.logger.warning(
                            f"[BASELINE POISONING] {src_mac} | PPS: {current_pps:.2f} | "
                            f"High-volume sample during baseline — blocking preemptively."
                        )
                        self._install_drop(datapath, src_mac)
                        blocked_this_cycle.add(src_mac)
                    continue
                else:
                    self.logger.info(
                        f"[BASELINE] {src_mac} | PPS: {current_pps:.2f} | "
                        f"Samples: {len(history)+1}/{MIN_HISTORY_POINTS} "
                        f"(building baseline...)"
                    )
                    history.append(current_pps)
                continue

            avg_pps  = sum(history) / len(history)
            variance = sum((x - avg_pps) ** 2 for x in history) / len(history)
            std_dev  = math.sqrt(variance)

            if std_dev == 0:
                self.logger.info(
                    f"[TRUST ENGINE] {src_mac} | PPS: {current_pps:.2f} | "
                    f"Baseline rock-stable | Z-Score: 0.00"
                )
                history.append(current_pps)
                if len(history) > HISTORY_WINDOW:
                    history.pop(0)
                continue

            z_score = (current_pps - avg_pps) / std_dev

            self.logger.info(
                f"[TRUST ENGINE] {src_mac} | "
                f"PPS: {current_pps:.2f} | "
                f"Avg: {avg_pps:.2f} | "
                f"StdDev: {std_dev:.2f} | "
                f"Z-Score: {z_score:.2f}"
            )

            if z_score > Z_SCORE_THRESHOLD and current_pps > MIN_PPS_THRESHOLD:
                self.logger.warning(
                    f"[ZERO-DAY THREAT] {src_mac} | "
                    f"Z-Score: {z_score:.2f} | PPS: {current_pps:.2f} | "
                    f"Statistical anomaly confirmed. DROPPING."
                )
                self._install_drop(datapath, src_mac)
                blocked_this_cycle.add(src_mac)
                # Victim MAC protection: also block any MAC with near-identical
                # PPS in this same batch (bidirectional reply traffic pattern)
                for other_mac, other_pps in batch.items():
                    if other_mac != src_mac and other_mac not in blocked_this_cycle:
                        if abs(other_pps - current_pps) / max(current_pps, 1) < 0.10:
                            # Set cooldown so this victim is immune for multiple polls
                            self.victim_cooldown[other_mac] = time.time()
                            self.known_victims.add(other_mac)  # permanent victim record
                            self.last_pkt_count.pop(other_mac, None)  # Clean counter
                            blocked_this_cycle.add(other_mac)
                            self.logger.info(
                                f"[VICTIM GUARD] {other_mac} protected — "
                                f"PPS ({other_pps:.2f}) mirrors attacker "
                                f"({current_pps:.2f}). Cooldown: {VICTIM_COOLDOWN_DURATION}s."
                            )
                continue  # Don't poison history with attack data

            # Normal traffic — append to rolling window
            history.append(current_pps)
            if len(history) > HISTORY_WINDOW:
                history.pop(0)

    # =========================================================================
    #  PERIODIC CLEANUP — Prevent Memory Leaks
    # =========================================================================

    def _cleanup_loop(self):
        """
        Background thread that periodically purges stale entries from
        last_pkt_count and src_dst_map for MACs that are no longer
        generating traffic. Runs every CLEANUP_INTERVAL seconds.
        """
        while True:
            hub.sleep(CLEANUP_INTERVAL)
            active_macs = set(self.host_history.keys())

            # Remove packet count entries for MACs not seen recently
            stale_pkt = [m for m in self.last_pkt_count if m not in active_macs]
            for m in stale_pkt:
                del self.last_pkt_count[m]

            # Reset CDR sets each cycle — prevents false positives from
            # accumulated historical connections across sessions
            for mac in list(self.src_dst_map.keys()):
                if mac not in active_macs:
                    del self.src_dst_map[mac]
                else:
                    # Keep the set but decay it — only last cycle's contacts matter
                    self.src_dst_map[mac] = set()

            # Purge victim_cooldown sentinel entries older than 2× cooldown duration
            # (kept longer than cooldown so recently_guarded check works post-expiry)
            stale_victims = [
                m for m, ts in self.victim_cooldown.items()
                if time.time() - ts > VICTIM_COOLDOWN_DURATION * 2
            ]
            for m in stale_victims:
                del self.victim_cooldown[m]

            if stale_pkt or stale_victims:
                self.logger.info(
                    f"[CLEANUP] Purged {len(stale_pkt)} stale MACs, "
                    f"{len(stale_victims)} expired victim sentinels."
                )
