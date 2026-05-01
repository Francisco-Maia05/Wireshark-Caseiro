class FilterEngine:
    def __init__(self, config: dict):
        self.protocol  = config.get('protocol')
        self.ip        = config.get('ip')
        self.mac       = config.get('mac')
        self.src_ip    = config.get('src_ip')
        self.dst_ip    = config.get('dst_ip')
        self.port      = config.get('port')
        self.tcp_flags = config.get('tcp_flags')

    def matches(self, parsed: dict) -> bool:
        """Retorna True se o pacote passa em todos os filtros ativos."""

        # ── Protocolo ─────────────────────────────────────────────────────────
        if self.protocol:
            proto = parsed.get('protocol', '').lower()
            tcp_family  = {'http'}
            udp_family  = {'dhcp'}
            if self.protocol == 'tcp'  and proto in tcp_family:
                pass
            elif self.protocol == 'udp' and proto in udp_family:
                pass
            elif self.protocol not in proto:
                return False

        # ── IP (src ou dst) ───────────────────────────────────────────────────
        if self.ip:
            if self.ip not in (parsed.get('src_ip', ''), parsed.get('dst_ip', '')):
                return False

        # ── IP origem / destino ───────────────────────────────────────────────
        if self.src_ip and parsed.get('src_ip') != self.src_ip:
            return False
        if self.dst_ip and parsed.get('dst_ip') != self.dst_ip:
            return False

        # ── MAC (src ou dst) ──────────────────────────────────────────────────
        if self.mac:
            mac_l = self.mac.lower()
            if mac_l not in (parsed.get('src_mac', '').lower(), parsed.get('dst_mac', '').lower()):
                return False

        # ── Porta TCP/UDP ─────────────────────────────────────────────────────
        if self.port is not None:
            p_src = parsed.get('src_port')
            p_dst = parsed.get('dst_port')
            if self.port not in (p_src, p_dst):
                return False

        # ── Flags TCP ─────────────────────────────────────────────────────────
        if self.tcp_flags:
            if parsed.get('protocol') not in ('TCP', 'HTTP'):
                return False
            
            pkt_flags = parsed.get('details', {}).get('flags', '')
            
            for flag in self.tcp_flags.upper():
                if flag not in pkt_flags:
                    return False

        return True