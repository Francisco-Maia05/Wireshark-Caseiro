#!/usr/bin/env python3
"""
RC Packet Sniffer — TP2, Redes de Computadores 2025/2026
Ponto de entrada principal e parsing de argumentos CLI.
"""

import argparse
import sys
import os

def parse_args():
    parser = argparse.ArgumentParser(
        prog='sniffer.py',
        description='RC Packet Sniffer — Redes de Computadores TP2',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  sudo python sniffer.py -i eth0
  sudo python sniffer.py -i eth0 --protocol icmp
  sudo python sniffer.py -i eth0 --protocol tcp --verbose
  sudo python sniffer.py -i eth0 --ip 192.168.1.1
  sudo python sniffer.py -i eth0 --src-ip 10.0.0.1 --dst-ip 10.0.0.2
  sudo python sniffer.py -i eth0 --mac aa:bb:cc:dd:ee:ff
  sudo python sniffer.py -i eth0 --bpf "port 53"
  sudo python sniffer.py -i eth0 --bpf "host 192.168.1.1 and tcp"
  sudo python sniffer.py -i eth0 --log captura.csv
  sudo python sniffer.py -i eth0 --log captura.json --log-format json
  sudo python sniffer.py -i eth0 --no-live --log captura.csv   # só ficheiro
  sudo python sniffer.py -i eth0 -c 50                         # 50 pacotes e para
  sudo python sniffer.py --list-interfaces
        """
    )

    # Utilitários
    parser.add_argument('--list-interfaces', action='store_true',
                        help='Lista as interfaces de rede disponíveis e sai')

    # Interface
    parser.add_argument('-i', '--interface',
                        help='Interface de rede a escutar (ex.: eth0, wlan0)')

    # ── Filtros ──────────────────────────────────────────────────────────────
    fg = parser.add_argument_group('Filtros')
    fg.add_argument('--protocol', metavar='PROTO',
                    help='Filtrar por protocolo: arp, icmp, icmpv6, tcp, udp, dns, dhcp, http, ipv4, ipv6')
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
                    help='Desativa a impressão em consola (útil quando só interessa o ficheiro)')
    og.add_argument('--log', metavar='FICHEIRO',
                    help='Guardar captura em ficheiro (ex.: captura.csv)')
    og.add_argument('--log-format', metavar='FMT', default='csv',
                    choices=['csv', 'json', 'txt'],
                    help='Formato do ficheiro de log: csv | json | txt  (default: csv)')
    og.add_argument('--verbose', '-v', action='store_true',
                    help='Mostrar detalhes adicionais de cada pacote')

    # ── Captura ───────────────────────────────────────────────────────────────
    cg = parser.add_argument_group('Captura')
    cg.add_argument('-c', '--count', type=int, default=0, metavar='N',
                    help='Parar após capturar N pacotes (0 = ilimitado)')

    return parser.parse_args()


def list_interfaces():
    """Mostra interfaces disponíveis usando Scapy."""
    from scapy.all import get_if_list, get_if_addr
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

    # ── Listar interfaces ─────────────────────────────────────────────────────
    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    # ── Verificar interface ───────────────────────────────────────────────────
    if not args.interface:
        print("[ERRO] Especifica uma interface com -i / --interface")
        print("       Usa --list-interfaces para ver as disponíveis.")
        sys.exit(1)

    # ── Aviso de permissões ───────────────────────────────────────────────────
    if os.name != 'nt' and os.geteuid() != 0:
        print("[AVISO] Para capturar pacotes é normalmente necessário executar como root (sudo).")

    # ── Importações tardias (evita lentidão no --list-interfaces / --help) ───
    from capture import SnifferEngine
    from logger import Logger
    from display import Display

    # Setup componentes
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

    # Banner inicial
    print(f"\n{'='*60}")
    print(f"  RC Packet Sniffer  |  interface: {args.interface}")
    if args.bpf:      print(f"  BPF filter  : {args.bpf}")
    if args.protocol: print(f"  Proto filter: {args.protocol.upper()}")
    if args.ip:       print(f"  IP filter   : {args.ip}")
    if args.log:      print(f"  Log file    : {args.log}  [{args.log_format.upper()}]")
    if args.count:    print(f"  Max packets : {args.count}")
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
        print(f"\n[*] Captura terminada — {engine.packet_count} pacote(s) registado(s).")
        if args.log:
            print(f"[*] Log guardado em: {args.log}")


if __name__ == '__main__':
    main()
