# RC Packet Sniffer — TP2
### Redes de Computadores 2025/2026 — Universidade do Minho

---

## Dependências

```bash
pip install scapy colorama
```

> **Nota:** `colorama` é opcional — sem ela o output fica sem cores mas funciona na mesma.

---

## Estrutura do projeto

```
packet_sniffer/
├── sniffer.py             # Ponto de entrada + CLI (argparse)
├── capture.py             # Motor de captura (wrapper Scapy sniff())
├── display.py             # Output colorido na consola (modo live)
├── logger.py              # Persistência em CSV / JSON / TXT
├── filters.py             # Filtros de alto nível (protocolo, IP, MAC)
├── protocols/
│   ├── __init__.py
│   └── analyzer.py        # Dispatcher + parsers por protocolo
└── README.md
```

---

## Protocolos suportados

| Protocolo | Camada | Identificação                            | Campos analisados                          |
|-----------|--------|------------------------------------------|--------------------------------------------|
| ARP       | L2/L3  | EtherType 0x0806                         | op (request/reply), sender/target IP & MAC |
| ICMP      | L3     | IP proto=1                               | type, code, id, seq                        |
| ICMPv6    | L3     | IPv6 next-header=58                      | Echo Req/Rep, NDP NS/NA/RA/RS              |
| IPv4      | L3     | EtherType 0x0800                         | src/dst, TTL, flags, proto                 |
| IPv6      | L3     | EtherType 0x86DD                         | src/dst, hop-limit, next-header            |
| TCP       | L4     | IP proto=6                               | flags (SYN/ACK/FIN/RST), seq, ack, window  |
| UDP       | L4     | IP proto=17                              | src/dst port, length                       |
| DNS       | L7     | UDP porta 53                             | query/response, qname, qtype, respostas    |
| DHCP      | L7     | UDP portas 67/68                         | message-type, IP oferecido, lease-time     |
| HTTP      | L7     | TCP porta 80/8080 + payload              | método, URI, status line                   |

---

## Utilização

> **Requer root/sudo** para captura em interface real.

### Sintaxe geral

```bash
sudo python sniffer.py -i <interface> [opções]
```

### Ver interfaces disponíveis

```bash
python sniffer.py --list-interfaces
```

### Exemplos

```bash
# Captura básica em eth0
sudo python sniffer.py -i eth0

# Verbose (mostra detalhes extra de cada pacote)
sudo python sniffer.py -i eth0 --verbose

# ── Filtros ────────────────────────────────────────────────────────────────

# Só pacotes ICMP
sudo python sniffer.py -i eth0 --protocol icmp

# Só pacotes TCP (inclui HTTP)
sudo python sniffer.py -i eth0 --protocol tcp

# Por IP (src ou dst)
sudo python sniffer.py -i eth0 --ip 192.168.1.1

# Por IP de origem específico
sudo python sniffer.py -i eth0 --src-ip 10.0.0.1

# Por IP de destino específico
sudo python sniffer.py -i eth0 --dst-ip 10.0.0.2

# Por MAC address
sudo python sniffer.py -i eth0 --mac aa:bb:cc:dd:ee:ff

# Filtro BPF (passado diretamente ao Scapy / libpcap)
sudo python sniffer.py -i eth0 --bpf "port 53"
sudo python sniffer.py -i eth0 --bpf "host 192.168.1.1 and tcp"
sudo python sniffer.py -i eth0 --bpf "not arp"
sudo python sniffer.py -i eth0 --bpf "udp port 67 or udp port 68"

# ── Logging ────────────────────────────────────────────────────────────────

# Log em CSV (default)
sudo python sniffer.py -i eth0 --log captura.csv

# Log em JSON (inclui campo 'details' com dados extra)
sudo python sniffer.py -i eth0 --log captura.json --log-format json

# Log em TXT (human-readable)
sudo python sniffer.py -i eth0 --log captura.txt --log-format txt

# Só log, sem output na consola
sudo python sniffer.py -i eth0 --no-live --log captura.csv

# Live + log em simultâneo (ambos ativos)
sudo python sniffer.py -i eth0 --log captura.json --log-format json

# ── Captura limitada ───────────────────────────────────────────────────────

# Parar após 100 pacotes
sudo python sniffer.py -i eth0 -c 100

# 50 pacotes ICMP e guarda em JSON
sudo python sniffer.py -i eth0 --protocol icmp -c 50 --log icmp.json --log-format json
```

---

## Execução no CORE

1. Na topologia CORE, abrir um terminal num nó (ex.: `n1`).
2. Identificar a interface com `ip a` (tipicamente `eth0`).
3. Copiar o sniffer para o nó (ou montar via shared folder).
4. Executar:

```bash
cd /path/to/packet_sniffer
python sniffer.py -i eth0 --log captura_core.csv
```

5. Noutros nós, gerar tráfego:

```bash
# ARP + ICMP
ping 10.0.0.2

# DNS
nslookup google.com

# TCP/HTTP
curl http://10.0.0.2

# DHCP (se houver servidor DHCP na rede)
dhclient eth0
```

---

## Execução no PC (interface real)

```bash
# Descobrir interface Wi-Fi / Ethernet
python sniffer.py --list-interfaces

# Exemplo com Wi-Fi
sudo python sniffer.py -i wlan0 --log captura_real.csv

# Capturar só DNS durante 60s (via Ctrl+C)
sudo python sniffer.py -i wlan0 --protocol dns --verbose
```

> **Atenção:** usar apenas em redes autorizadas (rede doméstica / CORE).
> Não recolher dados de terceiros nem desenvolver funcionalidades ativas (MITM, injection).

---

## Formato dos ficheiros de log

### CSV
```
index,timestamp,relative_time,interface,protocol,src_mac,dst_mac,src_ip,dst_ip,src_port,dst_port,size,summary
1,2025-04-01 10:00:00.123,0.000,eth0,ARP,...
```

### JSON
```json
[
  {
    "index": 1,
    "timestamp": "2025-04-01 10:00:00.123",
    "relative_time": 0.0,
    "protocol": "ARP",
    "summary": "ARP request: quem tem 10.0.0.2? → 10.0.0.1",
    "details": { "operação": "request", ... }
  }
]
```

### TXT
```
[     1] 2025-04-01 10:00:00.123 (+0.000s) [eth0] [ARP     ] 10.0.0.1 → 10.0.0.2 | 42 bytes | ARP request...
```
