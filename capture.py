"""
Motor de captura de pacotes usando Scapy.
Responsável por: iniciar a sniffagem, coordenar filtros, display e logging.
"""

import time
from scapy.sendrecv import sniff

from protocols.analyzer import PacketAnalyzer
from filters import FilterEngine


class SnifferEngine:
    """
    Orquestra a captura de pacotes.
    - Usa sniff() do Scapy com filtro BPF opcional.
    - Aplica filtros de alto nível.
    - Gere Estado (Interliga Pings e Fragmentos).
    """

    def __init__(self, interface, filter_config, display=None, logger=None, count=0):
        self.interface     = interface
        self.filter_config = filter_config
        self.display       = display
        self.logger        = logger
        self.count         = count

        self.packet_count  = 0
        self.start_time    = None
        self.end_time      = None
        self._running      = False

        self.total_bytes    = 0
        self.protocol_stats = {}

        # Guarda Pings Request (Chave: icmp_id_seq, Valor: index_do_pacote)
        self.icmp_requests = {}
        
        # Guarda Fragmentos IPv4 (Chave: ip_id, Valor: [lista_de_indices])
        self.ipv4_fragments = {}
        # ──────────────────────────────────────────────────────────────────────

        self.analyzer      = PacketAnalyzer()
        self.filter_engine = FilterEngine(filter_config)

    # ── API pública ───────────────────────────────────────────────────────────

    def start(self):
        self._running  = True
        self.start_time = time.time()

        bpf = self.filter_config.get('bpf') or None

        sniff(
            iface=self.interface,
            filter=bpf,
            prn=self._process_packet,
            count=self.count if self.count > 0 else 0,
            store=False,
            stop_filter=lambda _: not self._running,
        )

    def stop(self):
        self._running = False
        self.end_time = time.time()

    # ── Processamento interno ─────────────────────────────────────────────────

    def _process_packet(self, packet):
        parsed = self.analyzer.analyze(packet, self.interface, self.start_time)
        if parsed is None:
            return

        if not self.filter_engine.matches(parsed):
            return

        if self.filter_config.get('fragmented'):
            if 'Fragmento' not in parsed.get('summary', ''):
                return

        self.packet_count += 1
        parsed['index'] = self.packet_count
        current_idx = self.packet_count

        proto = parsed.get('protocol', '')
        details = parsed.get('details', {})

        if proto == 'ICMP':
            icmp_type = details.get('type')
            icmp_id = details.get('icmp_id')
            icmp_seq = details.get('icmp_seq')
            
            if icmp_id is not None and icmp_seq is not None:
                conv_key = f"{icmp_id}_{icmp_seq}"

                if icmp_type == 8: # Echo Request
                    self.icmp_requests[conv_key] = current_idx
                
                elif icmp_type == 0: # Echo Reply
                    if conv_key in self.icmp_requests:
                        req_idx = self.icmp_requests[conv_key]
                        parsed['summary'] += f" (Reply ao pacote #{req_idx})"

        if 'Fragmento' in parsed.get('summary', ''):
            ip_id = details.get('ip_id')
            if ip_id is not None:
                if ip_id not in self.ipv4_fragments:
                    self.ipv4_fragments[ip_id] = []
                self.ipv4_fragments[ip_id].append(current_idx)
                
                num_frag = len(self.ipv4_fragments[ip_id])
                if num_frag > 1:
                    anteriores = self.ipv4_fragments[ip_id][:-1]
                    lista_str = ", #".join(map(str, anteriores))
                    parsed['summary'] += f" [Fragmento {num_frag} associado ao #{lista_str}]"
                else:
                    parsed['summary'] += f" [Início da Fragmentação]"
        # ──────────────────────────────────────────────────────────────────────

        # Atualizar Estatísticas de Hierarquia
        size = parsed.get('size', 0)
        self.total_bytes += size
        
        if proto not in self.protocol_stats:
            self.protocol_stats[proto] = {'pkts': 0, 'bytes': 0}
            
        self.protocol_stats[proto]['pkts'] += 1
        self.protocol_stats[proto]['bytes'] += size

        # Output Visual e Logging
        if self.display:
            self.display.print_packet(parsed)

        if self.logger:
            self.logger.write(parsed)