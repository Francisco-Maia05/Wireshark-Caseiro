"""
Analisador central de protocolos.
Recebe um pacote Scapy e retorna um dicionário normalizado com:
  timestamp, interface, protocolo, MACs, IPs, portas, tamanho, resumo, detalhes.

Hierarquia de identificação (do mais específico para o mais geral):
  Ethernet → ARP / IPv4
  IPv4     → ICMP / TCP / UDP
  TCP      → HTTP  (porta 80/8080)
  UDP      → DHCP (portas 67-68)
"""

import time
from datetime import datetime

# Importações específicas por módulo
from scapy.layers.l2   import Ether, ARP
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.packet      import Raw

# DHCP — módulo separado
try:
    from scapy.layers.dhcp import DHCP, BOOTP
    _HAS_DHCP = True
except Exception:
    _HAS_DHCP = False
    DHCP = BOOTP = None


class PacketAnalyzer:
    """Converte um pacote Scapy num dicionário normalizado."""

    def analyze(self, packet, interface: str, start_time: float) -> dict | None:
        now = time.time()
        result = {
            'raw':           packet,
            'interface':     interface,
            'timestamp':     datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'relative_time': round(now - start_time, 6) if start_time else 0.0,
            'size':          len(packet),
            'protocol':      'Unknown',
            'src_mac':       '',
            'dst_mac':       '',
            'src_ip':        '',
            'dst_ip':        '',
            'src_port':      '',
            'dst_port':      '',
            'summary':       '',
            'details':       {},
        }

        # ── Camada 2: Ethernet ────────────────────────────────────────────────
        if packet.haslayer(Ether):
            eth = packet[Ether]
            result['src_mac'] = eth.src
            result['dst_mac'] = eth.dst
            result['protocol'] = 'Ethernet'

        # ── ARP ───────────────────────────────────────────────────────────────
        if packet.haslayer(ARP):
            return self._parse_arp(packet, result)

        # ── IPv4 ──────────────────────────────────────────────────────────────
        if packet.haslayer(IP):
            return self._parse_ipv4(packet, result)

        # Pacote sem camada reconhecida — ainda assim retornamos os dados de Ethernet
        result['summary'] = f"Ethernet {result['src_mac']} → {result['dst_mac']}"
        return result

    # ═══════════════════════════════════════════════════════════════════════════
    # ARP
    # ═══════════════════════════════════════════════════════════════════════════

    def _parse_arp(self, packet, r: dict) -> dict:
        arp = packet[ARP]
        op  = 'request' if arp.op == 1 else 'reply'

        r['protocol'] = 'ARP'
        r['src_ip']   = arp.psrc
        r['dst_ip']   = arp.pdst
        r['src_mac']  = arp.hwsrc
        r['dst_mac']  = arp.hwdst

        if op == 'request':
            r['summary'] = f"ARP Request: MAC {arp.hwsrc} pergunta quem tem o IP {arp.pdst}"
        else:
            r['summary'] = f"ARP Reply: IP {arp.psrc} está no MAC {arp.hwsrc} (Destino: {arp.hwdst})"

        r['details'] = {
            'operação':    op,
            'sender_mac':  arp.hwsrc,
            'sender_ip':   arp.psrc,
            'target_mac':  arp.hwdst,
            'target_ip':   arp.pdst,
        }
        return r

    # ═══════════════════════════════════════════════════════════════════════════
    # IPv4
    # ═══════════════════════════════════════════════════════════════════════════

    def _parse_ipv4(self, packet, r: dict) -> dict:
        ip = packet[IP]
        r['src_ip']  = ip.src
        r['dst_ip']  = ip.dst
        r['protocol'] = 'IPv4'
        r['details'] = {
            'ttl':   ip.ttl,
            'ip_id':    ip.id,
            'flags': str(ip.flags),
            'tos':   ip.tos,
        }

        if packet.haslayer(ICMP):
            return self._parse_icmp(packet, r)
        if packet.haslayer(TCP):
            return self._parse_tcp(packet, r)
        if packet.haslayer(UDP):
            return self._parse_udp(packet, r)

        r['summary'] = f"IPv4 {ip.src} → {ip.dst}  proto={ip.proto}"
        return r

    # ═══════════════════════════════════════════════════════════════════════════
    # ICMP
    # ═══════════════════════════════════════════════════════════════════════════

    ICMP_TYPES = {
        0:  'Echo Reply',
        3:  'Destination Unreachable',
        4:  'Source Quench',
        5:  'Redirect',
        8:  'Echo Request',
        11: 'Time Exceeded',
        12: 'Parameter Problem',
    }
    ICMP_UNREACH_CODES = {
        0: 'Net Unreachable',
        1: 'Host Unreachable',
        2: 'Protocol Unreachable',
        3: 'Port Unreachable',
    }

    def _parse_icmp(self, packet, r: dict) -> dict:
        icmp = packet[ICMP]
        type_str = self.ICMP_TYPES.get(icmp.type, f'Type {icmp.type}')
        r['protocol'] = 'ICMP'
        r['details'].update({
            'type':      icmp.type,
            'type_str':  type_str,
            'code':      icmp.code,
        })

        src, dst = r['src_ip'], r['dst_ip']

        if icmp.type in (0, 8):
            r['details']['icmp_id']  = icmp.id
            r['details']['icmp_seq'] = icmp.seq 
            r['summary'] = f"ICMP {type_str} {src} → {dst}  id={icmp.id} seq={icmp.seq}"
        elif icmp.type == 3:
            code_str = self.ICMP_UNREACH_CODES.get(icmp.code, f'code={icmp.code}')
            r['summary'] = f"ICMP {type_str} ({code_str}) {src} → {dst}"
        elif icmp.type == 11:
            r['summary'] = f"ICMP Time Exceeded {src} → {dst}"
        else:
            r['summary'] = f"ICMP {type_str} {src} → {dst}"

        return r

    # ═══════════════════════════════════════════════════════════════════════════
    # TCP
    # ═══════════════════════════════════════════════════════════════════════════

    def _parse_tcp(self, packet, r: dict) -> dict:
        tcp = packet[TCP]
        r['protocol']  = 'TCP'
        r['src_port']  = tcp.sport
        r['dst_port']  = tcp.dport

        flags     = self._decode_tcp_flags(tcp.flags)
        flags_str = ','.join(flags) if flags else '-'

        r['details'].update({
            'src_port': tcp.sport,
            'dst_port': tcp.dport,
            'flags':    flags_str,
            'seq':      tcp.seq,
            'ack':      tcp.ack,
            'window':   tcp.window,
        })

        # Sub-protocolos sobre TCP
        if tcp.dport in (80, 8080) or tcp.sport in (80, 8080):
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                http_verbs = (b'GET ', b'POST ', b'PUT ', b'DELETE ',
                              b'HEAD ', b'OPTIONS ', b'HTTP/')
                if any(payload.startswith(v) for v in http_verbs):
                    return self._parse_http(packet, r, tcp, payload)

        src, dst = r['src_ip'], r['dst_ip']
        base = f"TCP {src}:{tcp.sport} → {dst}:{tcp.dport} [{flags_str}]"

        note = ''
        if 'S' in flags and 'A' not in flags:
            note = ' ← SYN (início de ligação)'
        elif 'S' in flags and 'A' in flags:
            note = ' ← SYN-ACK (ligação aceite)'
        elif 'F' in flags and 'A' in flags:
            note = ' ← FIN-ACK (término)'
        elif 'F' in flags:
            note = ' ← FIN (término)'
        elif 'R' in flags:
            note = ' ← RST (reset)'

        r['summary'] = base + note
        return r

    # ═══════════════════════════════════════════════════════════════════════════
    # UDP
    # ═══════════════════════════════════════════════════════════════════════════

    def _parse_udp(self, packet, r: dict) -> dict:
        udp = packet[UDP]
        r['protocol'] = 'UDP'
        r['src_port'] = udp.sport
        r['dst_port'] = udp.dport
        r['details'].update({
            'src_port': udp.sport,
            'dst_port': udp.dport,
            'length':   udp.len,
        })

        if udp.dport in (67, 68) or udp.sport in (67, 68):
            if _HAS_DHCP and packet.haslayer(DHCP):
                return self._parse_dhcp(packet, r)

        r['summary'] = (
            f"UDP {r['src_ip']}:{udp.sport} → {r['dst_ip']}:{udp.dport}"
            f"  len={udp.len}"
        )
        return r

    # ═══════════════════════════════════════════════════════════════════════════
    # DHCP
    # ═══════════════════════════════════════════════════════════════════════════

    DHCP_MSG_TYPES = {
        1: 'Discover', 2: 'Offer',   3: 'Request', 4: 'Decline',
        5: 'ACK',      6: 'NAK',     7: 'Release', 8: 'Inform',
    }

    def _parse_dhcp(self, packet, r: dict) -> dict:
        dhcp = packet[DHCP]
        r['protocol'] = 'DHCP'

        msg_type = None
        for opt in dhcp.options:
            if isinstance(opt, tuple) and opt[0] == 'message-type':
                msg_type = opt[1]
                break

        type_str = self.DHCP_MSG_TYPES.get(msg_type, f'Type {msg_type}')
        r['details']['dhcp_type'] = type_str

        if packet.haslayer(BOOTP):
            bootp = packet[BOOTP]
            offered = bootp.yiaddr
            if offered and offered != '0.0.0.0':
                r['details']['offered_ip']  = offered
                r['summary'] = f"DHCP {type_str} → IP oferecido: {offered}"
            else:
                r['summary'] = f"DHCP {type_str}"
            for opt in dhcp.options:
                if isinstance(opt, tuple):
                    if opt[0] == 'server_id':
                        r['details']['dhcp_server'] = opt[1]
                    elif opt[0] == 'lease_time':
                        r['details']['lease_time'] = opt[1]
                    elif opt[0] == 'subnet_mask':
                        r['details']['subnet_mask'] = opt[1]
        else:
            r['summary'] = f"DHCP {type_str}"

        return r

    # ═══════════════════════════════════════════════════════════════════════════
    # HTTP
    # ═══════════════════════════════════════════════════════════════════════════

    def _parse_http(self, packet, r: dict, tcp, payload: bytes) -> dict:
        r['protocol'] = 'HTTP'
        try:
            first_line = payload.decode('utf-8', errors='replace').split('\r\n')[0]
            r['summary']               = f"HTTP {first_line}"
            r['details']['first_line'] = first_line
        except Exception:
            r['summary'] = (
                f"HTTP {r['src_ip']}:{tcp.sport} → {r['dst_ip']}:{tcp.dport}"
            )
        return r

    # ═══════════════════════════════════════════════════════════════════════════
    # Helpers
    # ═══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def _decode_tcp_flags(flags) -> list[str]:
        mapping = [
            ('F', 'FIN'), ('S', 'SYN'), ('R', 'RST'), ('P', 'PSH'),
            ('A', 'ACK'), ('U', 'URG'), ('E', 'ECE'), ('C', 'CWR'),
        ]
        flags_str = str(flags)
        return [short for short, _ in mapping if short in flags_str]