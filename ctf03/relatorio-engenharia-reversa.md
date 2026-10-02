# Engenharia Reversa e Otimização de Força Bruta em Flutter/Dart AOT
### Google CTF 2025 — "Fluffy" (categoria *reversing*)

> **Autor:** [seu nome] · **Disciplina:** Segurança Cibernética · **Data:** 29/09/2026
> **Alvo:** `fluffy.apk` (Android) — Dart 3.8.1 AOT · **Flag:** `CTF{Ok4y_h4v3_u_0ptim1zed_brUt3_f0rcE_0R_y0u_jUst_uSeD_a_l0t_0f_c0Res?}`

---

## Sumário

1. [Contexto e objetivos](#1-contexto-e-objetivos)
2. [Metodologia: do APK ao algoritmo](#2-metodologia-do-apk-ao-algoritmo)
3. [Análise criptográfica e redução do espaço de busca](#3-análise-criptográfica-e-redução-do-espaço-de-busca)
4. [Execução e resultados](#4-execução-e-resultados)
5. [Custo computacional comparado](#5-custo-computacional-comparado)
6. [Conclusões](#6-conclusões)
7. [Referências](#7-referências)
8. [Glossário](#8-glossário)

---

## 1. Contexto e objetivos

### 1.1 O desafio

O desafio fornece um aplicativo Android escrito em **Flutter** que implementa um cofre de segredos
com um **algoritmo de criptografia próprio** ("segurança por obscuridade"). O aplicativo é capaz de
**encriptar** segredos usando um **PIN** (4 dígitos, não nulo) e um **token** pseudoaleatório. A
funcionalidade de **decriptação** está incompleta ("em construção").

O aplicativo já vem com **três segredos pré-carregados**, que juntos contêm a *flag*:

```
fmMf7mIMbHcPoQmLGx1CO0XVGBmhjTaYhB0     (04/08/2023 13:37)
5O6WRgCajs3QSTyohnu2hldds18mjkx         (07/09/2024 18:52)
fgv99dOvazsvEESh7DPKbb3k0I3RW          (03/03/2025 22:07)
```

### 1.2 Objetivos

1. **Localizar** o algoritmo de criptografia dentro do binário compilado (AOT) `libapp.so`.
2. **Reconstruir** o token e a cifra a partir do binário.
3. **Recuperar** os três segredos (e, portanto, a flag) **sem** conhecer o PIN nem o token.
4. **Justificar formalmente** a redução do espaço de busca (período 16, conjuntos de PIN mod 8).
5. **Medir** o custo computacional e compará-lo com a força bruta ingênua.

> **Nota ética/legal:** trata-se de um desafio **público e já encerrado**, com *write-up* oficial e
> código-fonte liberados pela organização (Google CTF). A análise é autorizada e tem finalidade
> exclusivamente educacional.

---

## 2. Metodologia: do APK ao algoritmo

### 2.1 Extração do APK

```
$ unzip fluffy.apk -d fluffy_extracted
$ ls fluffy_extracted/lib/
arm64-v8a/  armeabi-v7a/  x86_64/
$ ls fluffy_extracted/lib/x86_64/
libapp.so  libflutter.so
```

O `libapp.so` (≈ 20 MB descompactado) concentra a lógica da aplicação.

### 2.2 Âncoras de string — o ponto de entrada

Como o AOT preserva strings na seção de dados da snapshot, uma varredura de `strings` revela
âncoras que levam diretamente ao código-alvo:

```
$ strings libapp.so | grep -iE 'gctf|Base62|Invalid character|PIN'
```

| Âncora (string) | Função que a referencia | O que revela |
|---|---|---|
| `gctf25_` | `generateToken()` | o **seed** do token (KDF) |
| `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz` | `Base62Encoder` | o **alfabeto** e o tamanho da base (62) |
| `Invalid character in Base62 string` | `Base62Encoder.decode` | dica deixada *de propósito* no código |
| `PIN must be exactly4  digits` / `For security reasons, PIN cannot be 0000` | `EncryptSecretPage` | as **regras do PIN** (4 dígitos, não nulo) |

Com as referências cruzadas (`xrefs`) a essas strings em um disassembler (`ghidra`, `radare2`),
identifica-se o código que as usa e, por proximidade, as funções `rol8`, `ror8` e o loop de `pin`
rodadas.

### 2.3 Ferramenta compatível com Dart 3.8.1

- **`blutter`** — reconstrói nomes de classes/funções a partir da snapshot mesmo sem símbolos.
  **Requisito:** compilado contra o SDK Dart compatível com a versão da snapshot
  (`830f4f59…`, Dart 3.8.1). Alternativas: **`darter`** (parser de snapshot), **`reFlutter`**.
- **`frida`** com hooks Dart para análise dinâmica (observar o valor do token/PIN em tempo de
  execução, se desejado).

### 2.4 Algoritmo reconstruído (Dart)

A partir do binário, reconstruiu-se o seguinte código (equivalente ao fonte liberado):

```dart
int rol8(int value, int shift) {
  final int s = shift & 7;
  return ((value << s) | (value >> (8 - s))) & 0xFF;
}
int ror8(int value, int shift) {
  final int s = shift & 7;
  return ((value >> s) | (value << (8 - s))) & 0xFF;
}

String generateToken() {
  final t = (DateTime.now().millisecondsSinceEpoch ~/ 1000).toString();
  final d = sha1.convert(utf8.encode("gctf25_$t"));
  return Base62Encoder.encode(Uint8List.fromList(d.bytes).sublist(0, 8));
}

class CustomEncrypt {
  final String token;
  final int pin;

  String encrypt(String secret) {
    List<int> dynToken  = Base62Encoder.decode(token);
    List<int> encrSecret = secret.codeUnits.toList();

    for (int i = 0; i < pin; i++) {
      for (int j = 0; j < encrSecret.length; j++) {
        encrSecret[j] = rol8((encrSecret[j] + dynToken[j % dynToken.length]) % 256, j % 8);
      }
      encrSecret = [encrSecret.last, ...encrSecret.sublist(0, encrSecret.length - 1)];
      dynToken   = [...dynToken.sublist(1), dynToken.first];
      dynToken   = [for (final d in dynToken) ror8(d, (pin ^ ((i & 3) + 1)) % 8)];
    }
    return Base62Encoder.encode(Uint8List.fromList(encrSecret));
  }
}
```

**Verificação de reconstrução (round-trip):** encriptar o 1º pedaço da flag com
`token = I6X6vyQzRuH` e `pin = 8126` reproduz **byte a byte** o ciphertext
`fmMf7mIMbHcPoQmLGx1CO0XVGBmhjTaYhB0`; a decriptação inverte corretamente. Isso prova que o
algoritmo reconstruído é idêntico ao original.

---

## 3. Análise criptográfica e redução do espaço de busca

### 3.1 O espaço de chaves

Não conhecemos o `PIN` nem o `token`. O PIN é de 4 dígitos não nulos ⇒ **9999** valores. O token é
função do segundo ⇒ **60** candidatos por segredo (dado o minuto exibido). Espaço bruto:
`9999 × 60 ≈ 6×10⁵` combinações.

### 3.2 Redução por timestamp (60 segundos + fuso horário)

O 1º segredo exibe `04/08/2023 13:37` **com os segundos** — dica explícita. A descrição do desafio
menciona um "amigo da Suíça" ⇒ fuso **Europe/Zurich**. O timestamp Unix é reconstruído
convertendo a data local (DD/MM/AAAA HH:MM) em Zurique, e testando os **60 segundos** do minuto:

```python
def generate_timestamp(time_str):
    dt = datetime.datetime.strptime(time_str, '%d/%m/%Y %H:%M')
    dt = dt.replace(tzinfo=zoneinfo.ZoneInfo("Europe/Zurich"))
    return int(datetime.datetime.timestamp(dt))
```

### 3.3 Período 16 — prova formal

A rotação de bits na rodada `i` é

```
r_i = (pin ^ ((i & 3) + 1)) % 8
```

que depende apenas de `k = pin mod 8` e de `i mod 4`. Defina `k = pin mod 8`.

**(a) Periodicidade da rotação.** `(i & 3) = i mod 4` tem período 4, logo `r_i` tem **período 4**.
Sejam os 4 valores `r₀,r₁,r₂,r₃`. Medindo para cada `k`:

| `k = pin mod 8` | `(r₀,r₁,r₂,r₃)` | soma em 4 | soma em 16 (`4×`) | soma em 8 (`2×`) |
|---|---|---|---|---|
| 0 | (1,2,3,4) | 10 | **40** | 20 |
| 1 | (0,3,2,5) | 10 | **40** | 20 |
| 2 | (3,0,1,6) | 10 | **40** | 20 |
| 3 | (2,1,0,7) | 10 | **40** | 20 |
| 4 | (5,6,7,0) | 18 | **72** | 36 |
| 5 | (4,7,6,1) | 18 | **72** | 36 |
| 6 | (7,4,5,2) | 18 | **72** | 36 |
| 7 | (6,5,4,3) | 18 | **72** | 36 |

**(b) Estado do `dynToken`.** O estado é totalmente descrito por dois números independentes:

1. o **deslocamento do array** (`i mod 8`) — as rotações esquerda do array;
2. a **rotação de bits acumulada** `S_i = Σ_{t< i} r_t (mod 8)` — a mesma para todos os 8 bytes.

O estado **repete** quando simultaneamente `i ≡ 0 (mod 8)` **e** `S_i ≡ 0 (mod 8)`.

**(c) Em `i = 8`:** o array volta à ordem original, mas `S₈ = 2×(soma de 4) = 20` ou `36`, ambos
`≡ 4 (mod 8) ≠ 0` ⇒ os bytes estão rotacionados 4 bits ⇒ **não** repete.

**(d) Em `i = 16`:** o array volta à ordem original (16 = 2×8), e `S₁₆ = 4×(soma de 4) = 40` ou
`72`, ambos `≡ 0 (mod 8)` ⇒ os bytes retornam à forma original.

**Conclusão:** o `dynToken` tem **período exato 16** (não 8). Isso significa que só existem **16
estados** de token por agenda `k` — não um estado novo a cada rodada até 9999.

### 3.4 Conjuntos de PIN mod 8

Como `r_i` depende de `k = pin mod 8`, existem apenas **8 agendas** de rotação distintas. Gerando,
para um token fixo, os estados alcançados nas 16 rodadas para cada `k`, e agrupando estados
idênticos:

- **40 estados** distintos de `dynToken` no total;
- **8 estados** são alcançáveis sob **todos** os 8 valores de `k`;
- **32 estados** são alcançáveis sob **exatamente 2** valores de `k`.

Logo o número de pares `(estado, agenda)` a testar é

```
8 × 8  +  32 × 2  =  128        (e não 40 × 8 = 320)
```

(Resultado medido diretamente, ex.: token `I6X6vyQzRuH` → distribuição `{8: 8, 2: 32}`.)

### 3.5 Modelo de custo

**Ingênua (recalcula do zero para cada PIN).** Para cada PIN `p`, decriptar custa `p` rodadas:

```
custo_por_token = Σ_{p=1}^{9999} p = 9999·10000/2 = 49 995 000 ≈ 5,0×10⁷
custo_total     = 60 × 49 995 000 ≈ 3,0×10⁹ operações de rodada
```

**Otimizada (explora o período 16).** Pré-computam-se os 40 estados finais de token (constante) e,
para cada um dos 128 pares `(estado, agenda)`, caminha-se **para trás** rodada a rodada, testando a
cada passo se o texto já é "printable" (oráculo §3.6). Custo por token:

```
128 × 9999 ≈ 1,28×10⁶ operações      →  speedup ≈ 49,995,000 / 1,279,872 ≈ 39×
custo_total = 60 × 1,28×10⁶ ≈ 7,7×10⁷ operações
```

A decriptação reversa usa uma tabela `inv_rot[pin_mod][i % 4]` que inverte a rotação de bits em
O(1), sem simular o token desde o início.

### 3.6 O oráculo de "printable ASCII"

Como não conhecemos o texto claro, usamos como **oráculo de sucesso** a propriedade de que a flag é
ASCII imprimível (`0x20–0x7E`): durante a decriptação reversa, o primeiro estado em que **todos** os
bytes forem imprimíveis corresponde ao PIN correto (o número de passos de volta = PIN). Para
segredos curtos pode haver raros falsos positivos, mas nestes três casos o oráculo é inequívoco.

---

## 4. Execução e resultados

### 4.1 Ambiente

- **CPU:** AMD Ryzen 7 5700X3D (8 núcleos) · **SO:** Windows 11
- **Python 3.14**, solver oficial `crack.py` (Google CTF), 3 processos em paralelo.

### 4.2 Segredos recuperados

| Segredo | Data (exibida) | segundo | PIN | Token derivado | Texto claro |
|---|---|---|---|---|---|
| 1 | 04/08/2023 13:37 | 27 | 8126 | `I6X6vyQzRuH` | `CTF{Ok4y_h4v3_u_0ptim1zed_` |
| 2 | 07/09/2024 18:52 | 31 | 5178 | `BMiZFI8Xr3Q` | `brUt3_f0rcE_0R_y0u_jUst` |
| 3 | 03/03/2025 22:07 | 48 | 7490 | `KZ95PpF1RFq` | `_uSeD_a_l0t_0f_c0Res?}` |

### 4.3 Flag

```
CTF{Ok4y_h4v3_u_0ptim1zed_brUt3_f0rcE_0R_y0u_jUst_uSeD_a_l0t_0f_c0Res?}
```

### 4.4 Custos medidos (força bruta completa, 60 segundos varridos)

| Segredo | Tempo de execução medido |
|---|---|
| 1 | 378 s |
| 2 | 394 s |
| 3 | 535 s |

O 3º segredo é o mais caro porque o segundo correto (48) só é atingido após varrer ~48 dos 60
segundos — cada segundo incorre no custo completo dos 128 pares antes de descartar o token.

---

## 5. Custo computacional comparado

| Estratégia | Operações de rodada (total) | Fator |
|---|---|---|
| Força bruta ingênua (recalcula por PIN) | `≈ 3,0 × 10⁹` | 1× (baseline) |
| Redução por período 16 + PIN mod 8 | `≈ 7,7 × 10⁷` | **≈ 39× menos** |

A redução **não** muda o número de combinações de chave (`60 × 9999`); ela elimina o **trabalho
redundante** de recomputar `PIN` rodadas a cada candidato, reaproveitando o ciclo de período 16 do
token. É exatamente a distinção que o desafio pede para demonstrar: **"você otimizou a força bruta,
ou só usou muitos núcleos?"** — a resposta técnica é a primeira.

---

## 6. Conclusões

1. O algoritmo foi **localizado e reconstruído** a partir do `libapp.so` (Dart AOT) usando âncoras
   de string (`gctf25_`, alfabeto Base62, mensagens de erro), e **validado por round-trip**.
2. A "aleatoriedade" do token é **ilusória**: ele é uma KDF determinística do timestamp (`SHA1` +
   Base62), reduzindo o espaço a 60 segundos por segredo (fuso `Europe/Zurich`).
3. A cifra tem **período estrutural 16** no token dinâmico, demonstrado formalmente pela
   periodicidade de `r_i` (período 4) e pela soma das rotações `≡ 0 (mod 8)` apenas em múltiplos de
   16 rodadas.
4. Explorar o período 16 + os **conjuntos de PIN mod 8** (8 estados universais + 32 estados com 2
   agendas = 128 pares) reduz o custo em **≈ 39×** frente à força bruta ingênua.
5. A flag foi recuperada integralmente, com custo **medido** de 378/394/535 s por segredo.

**Lição de segurança:** *security by obscurity* e KDFs previsíveis (baseadas em tempo) não oferecem
segurança real — a chave efetiva é minúscula (`60 × 9999`), e a estrutura periódica da cifra
permite quebrar o custo exponencial da força bruta.

---

## 7. Referências

- Google CTF 2025 — "Fluffy" (repositório, fonte e *write-up* oficial):
  `https://github.com/google/google-ctf/tree/1655538e8c8b41451d39f670ef15a5af22979ca9/2025/quals/rev-fluffy`
- Documentação Dart AOT / `gen_snapshot`: `https://dart.dev` (AOT compilation)
- `blutter` (reversão de Flutter/Dart AOT): `https://github.com/worawit/blutter`
- `darter` (parser de snapshot Dart): `https://github.com/mildsunrise/darter`
- `frida` (instrumentação dinâmica): `https://frida.re`
- Ghidra (disassembly/decompilação): `https://ghidra-sre.org`

---

## 8. Glossário

| Termo | Significado |
|---|---|
| **AOT** | *Ahead-Of-Time*: compilação para código nativo antes da execução. |
| **JIT** | *Just-In-Time*: compilação/interpretação durante a execução. |
| **APK** | Pacote de instalação Android (um ZIP padronizado). |
| **DEX** | Formato de bytecode executado pela ART (Java/Kotlin). |
| **Snapshot** | Blob com o *object pool* (strings, constantes, metadados) do runtime Dart. |
| **libapp.so** | Objeto ELF com o código Dart compilado (AOT). |
| **xref** | *Cross-reference*: referência de um endereço de código a um dado/string. |
| **Base62/Base64** | Codificação posicional em base 62/64. |
| **rol/ror** | *Rotate Left/Right*: rotação circular de bits. |
| **SHA-1** | Hash criptográfico de 160 bits. |
| **KDF** | *Key Derivation Function*: derivação de chave a partir de um segredo. |
| **Oráculo** | Condição observável que permite validar um candidato (aqui: ASCII imprimível). |
| **Periodicidade** | Repetição de estado após um número fixo de rodadas (aqui: 16). |
| **Speedup** | Razão entre o custo de duas abordagens. |
