#!/usr/bin/env python3

import json
import random
import time
from hashlib import sha256
from os import urandom
from Crypto.Cipher import AES

import ed25519

NUM_LEVELS = 16

RING_SIZE = 16

rand = random.SystemRandom()


def hexlify(inp):
    return inp.encode('latin-1').hex()


def unhexlify(inp):
    return bytes.fromhex(inp).decode('latin-1')


def public_key(sk):
    return hexlify(ed25519.encodepoint(ed25519.scalarmultbase(sk)))


def random_scalar():
    return rand.getrandbits(256)


def toPoint(hexVal):
    aa = unhexlify(hexVal)
    return ed25519.decodepoint(aa)


def scalarmult_simple(pk, num):
    return ed25519.encodepoint(ed25519.scalarmult(toPoint(pk), num))


def scalarmultKeyInt(pk, num):
    return hexlify(scalarmult_simple(pk, num))


def addKeys(P1, P2):
    return hexlify(ed25519.encodepoint(ed25519.edwards(toPoint(P1), toPoint(P2))))


def scalar_hash(val):
    return int(sha256(val.encode('latin-1')).hexdigest(), base=16)


def hash_to_point(val):
    return public_key(scalar_hash(val))


def key_image(privkey):
    return scalarmultKeyInt(hash_to_point(public_key(privkey)), privkey)

# Função mais importante para resolver
def ring_sign(message, public_keys, my_privkey, my_pubkey, my_index):
    image = key_image(my_privkey)

    sigc = [0 for xx in range(RING_SIZE)]
    sigr = [0 for xx in range(RING_SIZE)]

    buf = message
    sumc = 0

    for i in range(RING_SIZE):
        if i == my_index:
            q = random_scalar()

            L = public_key(q)
            R = scalarmultKeyInt(hash_to_point(my_pubkey), q)
        else:
            q = random_scalar()

            w = random_scalar()

            L = addKeys(public_key(q), scalarmultKeyInt(public_keys[i], w))
            R = addKeys(
                scalarmultKeyInt(hash_to_point(public_keys[i]), q),
                scalarmultKeyInt(image, w)
            )

            sigc[i] = w

            # se a chave usada para assinar "my_index" nao for a 15, a última iteração cairá aqui. Porém, isso significa que o valor de sigr[15] será q fora do loop.
            sigr[i] = q
            sumc += sigc[i]

        buf += L
        buf += R
        print(f"{i+1}/{RING_SIZE}")

    c = scalar_hash(buf)

    sigc[my_index] = (c - sumc) % ed25519.l

    # Ao invés de utilizar o gerado quando i == my_index, utiliza-se o valor de q que foi gerado na última iteração do loop, ou seja, utiliza-se sigr[15] (se i == 15 não for my_index). 
    sigr[my_index] = (q - sigc[my_index] * my_privkey) % ed25519.l

    return image, sigc, sigr
# após esse loop, o valor de q ainda se mantém, e é usado para calcular sigr[my_index] no final do loop. Isso é intencional, pois q é o valor aleatório gerado para a chave privada do usuário na posição my_index, e é necessário para calcular a assinatura correta.

# sendo rig_size = 16, a última iteração será i = 15.

'''
 Como usar o oráculo:

 1. Para descobrir o my_index, itera-se pelas 15 possibilidades utilizando a fórmula:

 my_privkey = (q - sigr[i]) * pow(sigc[i], -1, ed25519.l) % ed25519.l

 2. Com isso, gera-se uma chave "falsa" my_privkey para cada possibilidade. E, passando essa chave pela função key_image, obtém-se a chave pública correspondente. Se a chave pública gerada for igual à chave pública do nível, então o my_index correto foi encontrado.

 3. 
'''

def gen_ring(msg):
    public_keys = [public_key(random_scalar()) for i in range(RING_SIZE)]
    my_privkey = random_scalar()
    my_pubkey = public_key(my_privkey)
    my_index = random.randrange(0, len(public_keys))
    public_keys[my_index] = my_pubkey

    signature = ring_sign(msg, public_keys, my_privkey, my_pubkey, my_index)

    return signature, public_keys, my_index


def gen_levels():
    levels = []
    for level in range(NUM_LEVELS):
        msg = f"Generating ring {level}"
        print(msg)
        signature, pks, my_key = gen_ring(msg)
        levels.append({
            "signature": signature,
            "public_keys": pks,
            "my_key": my_key,
        })
        print(level)

    with open("flag.txt") as f:
        flag = f.read().strip().encode()

    # First byte of each of my public keys
    aes_key = bytes.fromhex("".join([l["public_keys"][l["my_key"]][0:2] for l in levels]))
    aes_iv = urandom(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    encrypted = cipher.encrypt(flag)

    output = {
        "levels": levels,
        "iv": aes_iv.hex(),
        "enc": encrypted.hex(),
    }

    with open("data-private.json", "w") as f:
        f.write(json.dumps(output))

    for level in output["levels"]:
        del level["my_key"]
    with open("data.json", "w") as f:
        f.write(json.dumps(output))

if __name__ == "__main__":
    gen_levels()
