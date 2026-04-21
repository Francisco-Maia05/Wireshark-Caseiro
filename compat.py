"""
Patch de compatibilidade — deve ser o PRIMEIRO import em qualquer ficheiro que use Scapy.

Problema: em alguns ambientes (CORE, containers, Python 3.12) a função
scapy.utils6.construct_source_candidate_set falha com KeyError: 'scope'
porque o kernel devolve entradas de endereços IPv6 sem o campo 'scope'.
Isto propaga-se para scapy.route6 → scapy.layers.inet e bloqueia todos os imports.

Solução: patch da função ANTES de scapy.route6 ser carregado.
"""

import sys


def _apply_scapy_patch():
    if sys.platform != 'linux':
        return

    try:
        # scapy.utils6 importa-se sem crash (não depende de route6)
        import scapy.utils6 as _utils6

        if getattr(_utils6, '_patched_by_compat', False):
            return  # já aplicado

        _orig = _utils6.construct_source_candidate_set

        def _safe_construct_source_candidate_set(prefix, plen, laddr, intf=None):
            """Versão defensiva: filtra entradas sem campo 'scope' em vez de crashar."""
            try:
                # Filtrar endereços que não têm 'scope' antes de passar para o original
                if isinstance(laddr, (list, tuple)):
                    laddr = [x for x in laddr if isinstance(x, dict) and 'scope' in x]
                return _orig(prefix, plen, laddr, intf)
            except Exception:
                return []

        _utils6.construct_source_candidate_set = _safe_construct_source_candidate_set
        _utils6._patched_by_compat = True

    except Exception:
        pass


_apply_scapy_patch()
