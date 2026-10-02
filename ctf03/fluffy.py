#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fluffy (Google CTF 2025) — implementação executável completa do algoritmo.

Este arquivo reproduz, em Python puro, o algoritmo reconstruído do libapp.so
(token, Base62 e a cifra) e o ataque de força bruta otimizado (período 16 +
conjuntos de PIN mod 8). Nenhuma dependência além da biblioteca padrão.

Uso:
    python fluffy.py demo
        Gera um token, encripta uma mensagem e decripta de volta (round-trip).

    python fluffy.py token 'DD/MM/AAAA HH:MM' <segundo>
        Gera o token de um instante específico (fuso Europe/Zurich).

    python fluffy.py crack 'DD/MM/AAAA HH:MM' '<ciphertext>' [--max-pin N]
        Recupera o segredo por força bruta otimizada.
        (sem --max-pin, usa N=10000 e leva ~6 min por segredo)
"""
import datetime
import hashlib
import sys
import zoneinfo

# -----------------------------------------------------------------------------
# Base62
# -----------------------------------------------------------------------------
ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
BASE = len(ALPHABET)  # 62
ALPHABET_MAP = {c: i for i, c in enumerate(ALPHABET)}


def rol8(v, n):
    """Rotação circular de 8 bits para a esquerda."""
    n &= 7
    return ((v << n) | (v >> (8 - n))) & 0xFF


def ror8(v, n):
    """Rotação circular de 8 bits para a direita."""
    n &= 7
    return ((v >> n) | (v << (8 - n))) & 0xFF


def base62_encode(data):
    """Codifica bytes (big-endian) em uma string Base62."""
    n = int.from_bytes(data, 'big')
    if n == 0:
        return '0'
    out = []
    while n > 0:
        n, r = divmod(n, BASE)
        out.append(ALPHABET[r])
    return ''.join(reversed(out))


def base62_decode(s):
    """Decodifica uma string Base62 de volta para bytes (big-endian)."""
    n = 0
    for ch in s:
        n = n * BASE + ALPHABET_MAP[ch]
    if n == 0:
        return b''
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, 'big')


# -----------------------------------------------------------------------------
# Token (KDF derivado do timestamp)
# -----------------------------------------------------------------------------
def generate_token(timestamp):
    """token = Base62( SHA1('gctf25_' + str(timestamp))[:8] )"""
    digest = hashlib.sha1(f'gctf25_{timestamp}'.encode('utf8')).digest()[:8]
    return base62_encode(digest)


def generate_timestamp(time_str):
    """Converte 'DD/MM/AAAA HH:MM' (fuso Europe/Zurich) em timestamp Unix (s)."""
    dt = datetime.datetime.strptime(time_str, '%d/%m/%Y %H:%M')
    dt = dt.replace(tzinfo=zoneinfo.ZoneInfo('Europe/Zurich'))
    return int(datetime.datetime.timestamp(dt))


# -----------------------------------------------------------------------------
# Cifra (encrypt/decrypt)
# -----------------------------------------------------------------------------
def encrypt(pin, token, secret):
    """Encripta `secret` (bytes) com `pin` e `token` (string Base62)."""
    dyn_token = list(base62_decode(token))
    encr = list(secret)

    for i in range(pin):
        encr = [
            rol8((s + dyn_token[j % len(dyn_token)]) % 256, j % 8)
            for j, s in enumerate(encr)
        ]
        encr = [encr[-1]] + encr[:-1]          # rotação direita do array
        dyn_token = dyn_token[1:] + [dyn_token[0]]  # rotação esquerda do array
        dyn_token = [ror8(d, (pin ^ ((i & 3) + 1)) % 8) for d in dyn_token]

    return base62_encode(bytes(encr))


def decrypt(pin, token, ciphertext):
    """Inverso de encrypt()."""
    secret = list(base62_decode(ciphertext))
    dyn_token = list(base62_decode(token))

    # Leva o token ao estado final (após `pin` rodadas).
    for i in range(pin - 1):
        dyn_token = dyn_token[1:] + [dyn_token[0]]
        dyn_token = [ror8(d, (pin ^ ((i & 3) + 1)) % 8) for d in dyn_token]

    for i in range(pin - 1, -1, -1):           # volta, da última à primeira rodada
        secret = secret[1:] + [secret[0]]
        secret = [
            (ror8(e, j % 8) - dyn_token[j % len(dyn_token)]) % 256
            for j, e in enumerate(secret)
        ]
        dyn_token = [rol8(d, (pin ^ (((i - 1) & 3) + 1)) % 8) for d in dyn_token]
        dyn_token = [dyn_token[-1]] + dyn_token[:-1]

    return bytes(secret)


# -----------------------------------------------------------------------------
# Ataque otimizado (período 16 + conjuntos de PIN mod 8)
# -----------------------------------------------------------------------------
def find_all_token_patterns(token):
    """Enumera os estados possíveis do token dinâmico (≤40) e seus `pin mod 8`.

    O token dinâmico repete a cada 16 rodadas. Para cada `k = pin mod 8`
    (0..7) geramos os 16 estados e agrupamos estados idênticos, registrando
    quais valores de `k` os produzem.
    """
    patterns = {}
    for pin_mod in range(8):
        dyn = list(base62_decode(token))
        for i in range(16):
            dyn = dyn[1:] + [dyn[0]]
            dyn = [ror8(d, (pin_mod ^ ((i & 3) + 1)) % 8) for d in dyn]
            key = bytes(dyn)
            _, pms = patterns.get(key, (None, []))
            patterns[key] = (dyn, pms + [pin_mod])
    return list(patterns.values())


# Tabela que inverte a rotação de bits de uma rodada, em O(1), ao caminhar de trás
# para frente. (equivalente a `(pin_mod ^ ((i & 3) + 1)) % 8` por rodada)
INV_ROT = [
    [3, 2, 1, 4],   # pin mod 8 = 0
    [5, 2, 3, 0],   # 1
    [3, 6, 1, 0],   # 2
    [1, 2, 7, 0],   # 3
    [7, 6, 5, 0],   # 4
    [1, 6, 7, 4],   # 5
    [7, 2, 5, 4],   # 6
    [5, 6, 3, 4],   # 7
]


def is_printable(b):
    return all(0x20 <= c <= 0x7E for c in b)


def crack(encr_secret, tok_patterns, max_pin=10000):
    """Recupera o texto claro testando (estado, agenda) e caminhando de trás p/ frente."""
    cipher = list(base62_decode(encr_secret))
    for tok_pat, pin_mods in tok_patterns:
        for pin_mod in pin_mods:
            dyn = tok_pat[:]
            secret = cipher[:]
            for step in range(max_pin):
                secret = secret[1:] + [secret[0]]
                secret = [
                    (ror8(e, j % 8) - dyn[j % len(dyn)]) % 256
                    for j, e in enumerate(secret)
                ]
                dyn = [rol8(d, INV_ROT[pin_mod][step % 4]) for d in dyn]
                dyn = [dyn[-1]] + dyn[:-1]
                if is_printable(secret):
                    return bytes(secret)
    return None


def crack_secret(time_str, encr_secret, max_pin=10000):
    """Varre os 60 segundos do minuto e, para cada token, tenta o crack."""
    base_ts = generate_timestamp(time_str)
    for second in range(60):
        token = generate_token(base_ts + second)
        print(f'[+] segundo {second:02d}/60  token={token}')
        secret = crack(encr_secret, find_all_token_patterns(token), max_pin)
        if secret is not None:
            return secret
    return None


# -----------------------------------------------------------------------------
# Modos de execução
# -----------------------------------------------------------------------------
def demo():
    print('=' * 60)
    print('DEMO — token, cifra e round-trip (1º segredo)')
    print('=' * 60)

    ts = generate_timestamp('04/08/2023 13:37') + 27
    token = generate_token(ts)
    pin = 8126
    plain = b'CTF{Ok4y_h4v3_u_0ptim1zed_'

    enc = encrypt(pin, token, plain)
    dec = decrypt(pin, token, enc)

    print(f'data+segundo : 04/08/2023 13:37 +27s  (unix={ts})')
    print(f'token        : {token}')
    print(f'PIN          : {pin}')
    print(f'texto claro  : {plain!r}')
    print(f'ciphertext   : {enc}')
    print(f'round-trip   : {dec!r}')
    print()
    print('round-trip OK' if dec == plain else 'round-trip FALHOU')
    print('ciphertext reproduzido:', 'OK' if enc == 'fmMf7mIMbHcPoQmLGx1CO0XVGBmhjTaYhB0' else 'FALHOU')


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    cmd = sys.argv[1]

    if cmd == 'demo':
        demo()
        return

    if cmd == 'token':
        if len(sys.argv) != 4:
            print("Uso: python fluffy.py token 'DD/MM/AAAA HH:MM' <segundo>")
            return
        ts = generate_timestamp(sys.argv[2]) + int(sys.argv[3])
        print(generate_token(ts))
        return

    if cmd == 'crack':
        if len(sys.argv) < 4:
            print("Uso: python fluffy.py crack 'DD/MM/AAAA HH:MM' '<ciphertext>' [--max-pin N]")
            return
        time_str, cipher = sys.argv[2], sys.argv[3]
        max_pin = 10000
        if '--max-pin' in sys.argv:
            max_pin = int(sys.argv[sys.argv.index('--max-pin') + 1])
        secret = crack_secret(time_str, cipher, max_pin)
        print(f'[+] Segredo: {secret}')
        return

    print(__doc__)


if __name__ == '__main__':
    main()
