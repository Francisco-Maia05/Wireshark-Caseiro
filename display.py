"""
Módulo de display — impressão colorida na consola (modo live).
"""

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    _HAS_COLOR = True
except ImportError:
    # Fallback sem cores se colorama não estiver instalada
    class _Dummy:
        def __getattr__(self, _): return ''
    Fore = Style = _Dummy()
    _HAS_COLOR = False


# Cor por protocolo
PROTO_COLOR = {
    'ARP':     Fore.YELLOW,
    'ICMP':    Fore.CYAN,
    'ICMPV6':  Fore.CYAN,
    'TCP':     Fore.GREEN,
    'UDP':     Fore.BLUE,
    'DNS':     Fore.MAGENTA,
    'DHCP':    Fore.LIGHTYELLOW_EX,
    'HTTP':    Fore.LIGHTCYAN_EX,
    'IPV4':    Fore.WHITE,
    'IPV6':    Fore.WHITE,
    'ETHERNET':Fore.WHITE,
}


class Display:
    """Imprime cada pacote numa linha formatada com cor."""

    HEADER = (
        f"{'#':<6} {'Tempo(s)':<11} {'Proto':<9} "
        f"{'Origem':<26} {'Destino':<26} {'Bytes':<6} Resumo"
    )
    SEP = "─" * 110

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        print(self.HEADER)
        print(self.SEP)

    # ── API pública ───────────────────────────────────────────────────────────

    def print_packet(self, parsed: dict):
        idx      = parsed.get('index', 0)
        t        = f"{parsed.get('relative_time', 0.0):.3f}"
        proto    = parsed.get('protocol', '?')
        src      = self._addr(parsed, 'src')
        dst      = self._addr(parsed, 'dst')
        size     = parsed.get('size', 0)
        summary  = parsed.get('summary', '')

        color = PROTO_COLOR.get(proto.upper(), Fore.WHITE)
        reset = Style.RESET_ALL

        line = (
            f"{idx:<6} {t:<11} "
            f"{color}{proto:<9}{reset} "
            f"{src:<26} {dst:<26} "
            f"{size:<6} {summary}"
        )
        print(line)

        if self.verbose and parsed.get('details'):
            dim = Fore.LIGHTBLACK_EX if _HAS_COLOR else ''
            for k, v in parsed['details'].items():
                print(f"         {dim}↳ {k}: {v}{reset}")

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _addr(parsed: dict, side: str) -> str:
        """Formata endereço como IP:porta ou só IP ou MAC."""
        ip   = parsed.get(f'{side}_ip',   '')
        port = parsed.get(f'{side}_port', '')
        mac  = parsed.get(f'{side}_mac',  '')
        if ip and port:
            return f"{ip}:{port}"
        if ip:
            return ip
        return mac or '-'
