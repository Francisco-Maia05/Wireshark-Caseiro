import argparse
import sys
import os
from datetime import datetime

try:
    import compat
except ImportError:
    pass

def parse_args():
    parser = argparse.ArgumentParser(
        prog='sniffer.py',
        description='RC Packet Sniffer — Redes de Computadores TP2',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  sudo python sniffer.py -i eth0
  sudo python sniffer.py -i eth0 --protocol icmp
  sudo python sniffer.py -i eth0 --protocol tcp -v
  sudo python sniffer.py -i eth0 --log captura.csv
  sudo python sniffer.py -i eth0 -c 50
        """
    )

    parser.add_argument('--list-interfaces', action='store_true',
                        help='Lista as interfaces de rede disponíveis e sai')
    
    parser.add_argument('-i', '--interface',
                        help='Interface de rede a escutar (ex.: eth0, wlan0)')

    fg = parser.add_argument_group('Filtros')
    fg.add_argument('--protocol', metavar='PROTO',
                    help='Filtrar por protocolo: arp, icmp, tcp, udp, dhcp, http, ipv4')
    fg.add_argument('--ip', metavar='ADDR',
                    help='Filtrar por endereço IP (src ou dst)')
    fg.add_argument('--src-ip', metavar='ADDR',
                    help='Filtrar por IP de origem')
    fg.add_argument('--dst-ip', metavar='ADDR',
                    help='Filtrar por IP de destino')
    fg.add_argument('--mac', metavar='ADDR',
                    help='Filtrar por endereço MAC (src ou dst)')
    fg.add_argument('--bpf', metavar='EXPR',
                    help='Expressão BPF passada diretamente ao Scapy (ex.: "port 80")')

    # ── Output ────────────────────────────────────────────────────────────────
    og = parser.add_argument_group('Output')
    og.add_argument('--no-live', action='store_true',
                    help='Desativa a impressão em consola')
    og.add_argument('--log', metavar='FICHEIRO',
                    help='Guardar captura em ficheiro')
    og.add_argument('--log-format', metavar='FMT', default='csv',
                    choices=['csv', 'json', 'txt'],
                    help='Formato do ficheiro de log (default: csv)')
    og.add_argument('--verbose', '-v', action='store_true',
                    help='Mostrar detalhes adicionais de cada pacote')

    # ── Captura ───────────────────────────────────────────────────────────────
    cg = parser.add_argument_group('Captura')
    cg.add_argument('-c', '--count', type=int, default=0, metavar='N',
                    help='Parar após capturar N pacotes (0 = ilimitado)')

    return parser.parse_args()


def list_interfaces():
    """Mostra interfaces disponíveis usando Scapy."""
    from scapy.arch import get_if_list, get_if_addr
    print("\nInterfaces disponíveis:")
    print(f"  {'Interface':<20} {'IP'}")
    print(f"  {'-'*20} {'-'*15}")
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
        except Exception:
            ip = 'N/A'
        print(f"  {iface:<20} {ip}")
    print()


def main():
    args = parse_args()

    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    if not args.interface:
        print("[ERRO] Especifica uma interface com -i / --interface")
        sys.exit(1)

    if os.name != 'nt' and os.geteuid() != 0:
        print("[AVISO] Execução como root (sudo) recomendada para captura real.")

    # Importações tardias
    from capture import SnifferEngine
    from logger import Logger
    from display import Display

    logger  = Logger(args.log, args.log_format) if args.log else None
    display = Display(verbose=args.verbose)     if not args.no_live else None

    filter_config = {
        'protocol': args.protocol.lower() if args.protocol else None,
        'ip':       args.ip,
        'mac':      args.mac,
        'src_ip':   args.src_ip,
        'dst_ip':   args.dst_ip,
        'bpf':      args.bpf,
    }

    engine = SnifferEngine(
        interface=args.interface,
        filter_config=filter_config,
        display=display,
        logger=logger,
        count=args.count,
    )

    print(f"\n{'='*60}")
    print(f"  RC Packet Sniffer  |  interface: {args.interface}")
    if args.log:      print(f"  Log file    : {args.log}  [{args.log_format.upper()}]")
    print(f"{'='*60}")
    print("  Ctrl+C para parar\n")

    try:
        engine.start()
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
        if logger:
            logger.close()

        print(f"\n{'='*85}")
        print(f"  RESUMO DA CAPTURA")
        print(f"{'='*85}")

        if engine.start_time and engine.end_time:
            duration = engine.end_time - engine.start_time
            start_dt = datetime.fromtimestamp(engine.start_time).strftime('%Y-%m-%d %H:%M:%S')
            
            print(f"  Início: {start_dt}  |  Duração: {duration:.2f}s  |  Total Pacotes: {engine.packet_count}")
            
            if engine.protocol_stats:

                # Definição das relações para construir a árvore
                PATHS = {
                    'HTTP':     ['Ethernet', 'IPv4', 'TCP', 'HTTP'],
                    'DHCP':     ['Ethernet', 'IPv4', 'UDP', 'DHCP'],
                    'TCP':      ['Ethernet', 'IPv4', 'TCP'],
                    'UDP':      ['Ethernet', 'IPv4', 'UDP'],
                    'ICMP':     ['Ethernet', 'IPv4', 'ICMP'],
                    'IPv4':     ['Ethernet', 'IPv4'],
                    'ARP':      ['Ethernet', 'ARP'],
                    'Ethernet': ['Ethernet']
                }

                tree = {'pkts': 0, 'bytes': 0, 'children': {}}
                for proto, stats in engine.protocol_stats.items():
                    path = PATHS.get(proto, ['Ethernet', proto])
                    current = tree
                    for node in path:
                        if node not in current['children']:
                            current['children'][node] = {'pkts': 0, 'bytes': 0, 'children': {}}
                        current = current['children'][node]
                        current['pkts']  += stats['pkts']
                        current['bytes'] += stats['bytes']

                print(f"\n  Hierarchy Statistics (Taxas Médias & Totais):")
                print(f"  {'Protocolo':<25} | {'Pacotes':<8} | {'% Pkts':<7} | {'Bytes':<10} | {'Tx (Pkts/s)':<11} | {'Tx (Bytes/s)'}")
                print(f"  {'-'*25}-+-{'-'*8}-+-{'-'*7}-+-{'-'*10}-+-{'-'*11}-+-{'-'*15}")


                def format_bytes(b):
                    
                    if b < 1024: return f"{b:.1f} B"
                    elif b < 1024**2: return f"{b/1024:.1f} KB"
                    else: return f"{b/(1024**2):.2f} MB"

                def print_tree(name, data, depth=0):
                    indent = "  " * depth
                    prefix = "└─ " if depth > 0 else ""
                    node_name = f"{indent}{prefix}{name}"
                    
                    pkts = data['pkts']
                    b_str = format_bytes(data['bytes'])
                    
                    perc = (pkts / engine.packet_count * 100) if engine.packet_count > 0 else 0
                    perc_str = f"{perc:.1f}%"

                    rate_p = pkts / duration if duration > 0 else 0
                    rate_b = data['bytes'] / duration if duration > 0 else 0
                    rb_str = format_bytes(rate_b) + "/s"
                    
                    print(f"  {node_name:<25} | {pkts:<8} | {perc_str:<7} | {b_str:<10} | {rate_p:<11.2f} | {rb_str}")
                    
                    for c_name, c_data in sorted(data['children'].items(), key=lambda x: x[1]['pkts'], reverse=True):
                        print_tree(c_name, c_data, depth + 1)

                for c_name, c_data in tree['children'].items():
                    print_tree(c_name, c_data)
        else:
            print("  Nenhum dado capturado.")

        print(f"{'='*85}")
        if args.log: print(f"[*] Ficheiro guardado: {args.log}")


if __name__ == '__main__':
    main()