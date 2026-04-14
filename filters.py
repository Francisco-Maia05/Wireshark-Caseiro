"""
Motor de filtros de alto nível.
Os filtros BPF são aplicados pelo Scapy diretamente no kernel (mais eficientes);
estes filtros aplicam-se depois, sobre os campos já parseados.
"""


class FilterEngine:
    def __init__(self, config: dict):
        self.protocol = config.get('protocol')           # ex.: 'tcp'
        self.ip       = config.get('ip')                 # src OU dst
        self.mac      = config.get('mac')                # src OU dst
        self.src_ip   = config.get('src_ip')
        self.dst_ip   = config.get('dst_ip')

    def matches(self, parsed: dict) -> bool:
        """Retorna True se o pacote passa em todos os filtros ativos."""

        # ── Protocolo ─────────────────────────────────────────────────────────
        if self.protocol:
            proto = parsed.get('protocol', '').lower()
            # suporte a sub-protocolos: "tcp" aceita "http" (que corre sobre TCP)
            tcp_family  = {'http'}
            udp_family  = {'dns', 'dhcp'}
            if self.protocol == 'tcp'  and proto in tcp_family:
                pass  # ok
            elif self.protocol == 'udp' and proto in udp_family:
                pass  # ok
            elif self.protocol not in proto:
                return False

        # ── IP (src ou dst) ───────────────────────────────────────────────────
        if self.ip:
            if self.ip not in (parsed.get('src_ip', ''), parsed.get('dst_ip', '')):
                return False

        # ── IP origem ─────────────────────────────────────────────────────────
        if self.src_ip and parsed.get('src_ip') != self.src_ip:
            return False

        # ── IP destino ────────────────────────────────────────────────────────
        if self.dst_ip and parsed.get('dst_ip') != self.dst_ip:
            return False

        # ── MAC (src ou dst) ──────────────────────────────────────────────────
        if self.mac:
            mac_l = self.mac.lower()
            if mac_l not in (
                parsed.get('src_mac', '').lower(),
                parsed.get('dst_mac', '').lower(),
            ):
                return False

        return True
