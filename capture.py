"""
Motor de captura de pacotes usando Scapy.
Responsável por: iniciar a sniffagem, coordenar filtros, display e logging.
"""

import time
from scapy.all import sniff

from protocols.analyzer import PacketAnalyzer
from filters import FilterEngine


class SnifferEngine:
    """
    Orquestra a captura de pacotes.
    - Usa sniff() do Scapy com filtro BPF opcional (eficiente, feito no kernel).
    - Aplica filtros adicionais de alto nível (protocolo, IP, MAC).
    - Delega análise ao PacketAnalyzer, display ao Display e persistência ao Logger.
    """

    def __init__(self, interface, filter_config, display=None, logger=None, count=0):
        self.interface     = interface
        self.filter_config = filter_config
        self.display       = display
        self.logger        = logger
        self.count         = count          # 0 = ilimitado
        self.packet_count  = 0
        self.start_time    = None
        self._running      = False
        self.analyzer      = PacketAnalyzer()
        self.filter_engine = FilterEngine(filter_config)

    # ── API pública ───────────────────────────────────────────────────────────

    def start(self):
        self._running  = True
        self.start_time = time.time()

        bpf = self.filter_config.get('bpf') or None   # None = sem filtro BPF

        sniff(
            iface=self.interface,
            filter=bpf,
            prn=self._process_packet,
            count=self.count if self.count > 0 else 0,
            store=False,                                # não acumular em RAM
            stop_filter=lambda _: not self._running,
        )

    def stop(self):
        self._running = False

    # ── Processamento interno ─────────────────────────────────────────────────

    def _process_packet(self, packet):
        parsed = self.analyzer.analyze(packet, self.interface, self.start_time)
        if parsed is None:
            return

        # Filtros de alto nível (protocolo, IP, MAC)
        if not self.filter_engine.matches(parsed):
            return

        self.packet_count += 1
        parsed['index'] = self.packet_count

        if self.display:
            self.display.print_packet(parsed)

        if self.logger:
            self.logger.write(parsed)
