# RC Packet Sniffer — TP2
### Redes de Computadores 2025/2026 — Universidade do Minho
### Grupo PL64 — Tomás Teles Coelho (A111262), Tomás Ramalhete (A98953), Francisco Maia (A108962)

---

## Dependências

```bash
pip install scapy colorama
```

> `colorama` é opcional — sem ela o output fica sem cores mas funciona na mesma.

---

## Estrutura do projeto

```
packet_sniffer/
├── sniffer.py          # Ponto de entrada + CLI (argparse)
├── capture.py          # Motor de captura (Scapy sniff()) + gestão de estado
├── display.py          # Output colorido na consola
├── logger.py           # Persistência em CSV / JSON / TXT
├── filters.py          # Filtros de alto nível
├── protocols/
│   └── analyzer.py     # Parsers por protocolo
└── README.md
```

---

## Protocolos suportados

| Protocolo | Camada | Campos analisados |
|-----------|--------|-------------------|
| ARP  | L2/L3 | op (request/reply), sender/target IP & MAC |
| IPv4 | L3    | src/dst, TTL, flags, fragmentação (ip_id) |
| ICMP | L3    | type, code, id, seq (correlação req/reply) |
| TCP  | L4    | flags (SYN/ACK/FIN/RST), seq, ack, window |
| UDP  | L4    | src/dst port, length |
| DHCP | L7    | message-type, IP oferecido, lease-time |
| HTTP | L7    | método, URI, status line |

---

## Utilização

> **Requer root/sudo** para captura em interface real.

```bash
# Sintaxe geral
sudo python sniffer.py -i <interface> [opções]

# Listar interfaces disponíveis
python sniffer.py --list-interfaces

# Exemplos de filtros
sudo python sniffer.py -i eth0 --protocol icmp
sudo python sniffer.py -i eth0 --ip 192.168.1.1
sudo python sniffer.py -i eth0 --src-ip 10.0.0.1
sudo python sniffer.py -i eth0 --dst-ip 10.0.0.2
sudo python sniffer.py -i eth0 --mac aa:bb:cc:dd:ee:ff
sudo python sniffer.py -i eth0 --port 53
sudo python sniffer.py -i eth0 --tcp-flags S
sudo python sniffer.py -i eth0 --fragmented
sudo python sniffer.py -i eth0 --bpf "host 192.168.1.1 and tcp"

# Logging (live + ficheiro em simultâneo)
sudo python sniffer.py -i eth0 --log captura.csv
sudo python sniffer.py -i eth0 --log captura.json --log-format json
sudo python sniffer.py -i eth0 --log captura.txt --log-format txt
sudo python sniffer.py -i eth0 --no-live --log captura.csv

# Limitar número de pacotes
sudo python sniffer.py -i eth0 -c 100
```

---

## Execução no CORE

Topologia: router central (n10) com três sub-redes — `10.0.0.0/24` (switch n5, nós n1/n2), `10.0.1.0/24` (switch n6, nós n3/n4) e `10.0.2.0/24` (nó n7 direto ao router).

```bash
# No nó sniffer
python sniffer.py -i eth0 --log captura_core.csv

# Gerar tráfego noutros nós
ping 10.0.0.2                        # ARP + ICMP
ping -c 1 -s 4000 10.0.0.20         # ICMP fragmentado
traceroute 10.0.0.20                 # UDP + ICMP Time Exceeded
nslookup google.com                  # DNS
python3 -m http.server 4444          # HTTP (no nó destino)
curl http://10.0.1.21:4444           # HTTP (no nó origem)
dhclient eth0                        # DHCP
```

---

## Execução no PC (interface real)

```bash
sudo python sniffer.py -i wlan0 --log captura_real.csv
sudo python sniffer.py -i wlan0 --port 53 --verbose
```

> Usar apenas em redes autorizadas. Em redes reais, recomenda-se o uso de filtros ou `--no-live` para evitar saturar o terminal.

---

## Funcionalidades opcionais

- **Correlação ICMP** — associa cada Echo Reply ao Request original (`Reply ao pacote #X`).
- **Agrupamento de fragmentos IPv4** — agrupa fragmentos pelo `ip_id`.
- **Rastreio do estado TCP** — anota SYN, SYN-ACK, FIN-ACK e RST.
- **Estatísticas finais** — tabela com pacotes, bytes e débito por protocolo ao terminar (Ctrl+C).

---

## Limitações

- HTTPS não é suportado (apenas HTTP em claro nas portas 80/8080).
- Requer privilégios de root/administrador para captura em interface real.
