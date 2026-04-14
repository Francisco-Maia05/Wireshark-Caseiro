"""
Módulo de logging — persiste capturas em CSV, JSON ou TXT.
Ambos os modos (live + log) podem estar ativos em simultâneo.
"""

import csv
import json
import os


# Campos exportados em CSV e JSON
CSV_FIELDS = [
    'index', 'timestamp', 'relative_time', 'interface',
    'protocol', 'src_mac', 'dst_mac',
    'src_ip', 'dst_ip', 'src_port', 'dst_port',
    'size', 'summary',
]


class Logger:
    """Escreve pacotes parseados num ficheiro de log."""

    def __init__(self, filepath: str, fmt: str = 'csv'):
        self.filepath = filepath
        self.fmt      = fmt.lower()
        self._count   = 0
        self._file    = None
        self._writer  = None
        self._open()

    # ── API pública ───────────────────────────────────────────────────────────

    def write(self, parsed: dict):
        self._count += 1
        try:
            if self.fmt == 'csv':
                self._write_csv(parsed)
            elif self.fmt == 'json':
                self._write_json(parsed)
            else:
                self._write_txt(parsed)
            self._file.flush()
        except Exception as e:
            print(f"[Logger] Erro ao escrever: {e}")

    def close(self):
        if self._file and not self._file.closed:
            if self.fmt == 'json':
                self._file.write('\n]\n')
            self._file.close()

    # ── Inicialização ─────────────────────────────────────────────────────────

    def _open(self):
        # Cria directórios se necessário
        dirpath = os.path.dirname(self.filepath)
        if dirpath:
            os.makedirs(dirpath, exist_ok=True)

        self._file = open(self.filepath, 'w', newline='', encoding='utf-8')

        if self.fmt == 'csv':
            self._writer = csv.DictWriter(self._file, fieldnames=CSV_FIELDS,
                                          extrasaction='ignore')
            self._writer.writeheader()

        elif self.fmt == 'json':
            self._file.write('[\n')

        elif self.fmt == 'txt':
            self._file.write(
                f"# RC Packet Sniffer — captura\n"
                f"# Formato: [índice] timestamp (+tempo_relativo) [iface] [proto] src → dst | bytes | resumo\n"
                f"{'#'*80}\n\n"
            )

    # ── Escritores por formato ────────────────────────────────────────────────

    def _write_csv(self, p: dict):
        row = {f: str(p.get(f, '')) for f in CSV_FIELDS}
        self._writer.writerow(row)

    def _write_json(self, p: dict):
        record = {
            'index':         p.get('index', self._count),
            'timestamp':     p.get('timestamp', ''),
            'relative_time': p.get('relative_time', 0),
            'interface':     p.get('interface', ''),
            'protocol':      p.get('protocol', ''),
            'src_mac':       p.get('src_mac', ''),
            'dst_mac':       p.get('dst_mac', ''),
            'src_ip':        p.get('src_ip', ''),
            'dst_ip':        p.get('dst_ip', ''),
            'src_port':      str(p.get('src_port', '')),
            'dst_port':      str(p.get('dst_port', '')),
            'size':          p.get('size', 0),
            'summary':       p.get('summary', ''),
            'details':       p.get('details', {}),
        }
        sep = '' if self._count == 1 else ','
        self._file.write(f"{sep}\n  {json.dumps(record, ensure_ascii=False)}")

    def _write_txt(self, p: dict):
        src = p.get('src_ip') or p.get('src_mac', '-')
        dst = p.get('dst_ip') or p.get('dst_mac', '-')
        line = (
            f"[{p.get('index', self._count):>6}] "
            f"{p.get('timestamp', '')} "
            f"(+{p.get('relative_time', 0):.3f}s) "
            f"[{p.get('interface', '')}] "
            f"[{p.get('protocol', '?'):<8}] "
            f"{src} → {dst} "
            f"| {p.get('size', 0)} bytes | "
            f"{p.get('summary', '')}\n"
        )
        self._file.write(line)
