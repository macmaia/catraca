---
name: False negative or known-limit bypass / Falso negativo ou desvio de limite conhecido
about: Untrusted content got through in a way the docs already describe as a limit / Conteúdo não confiável passou de um jeito que a documentação já descreve como limite
labels: bench-case
---

<!--
Real vulnerability (a guarantee broken, e.g. mode A, the egress gate, evidence chain or a default that isn't strict)? Please don't file it here, follow SECURITY.md.
This template is for bypasses that fall under the documented limits of mode B (paraphrase, translation, re-encoding it doesn't know). We add them to the case bank and publish them.

Vulnerabilidade de verdade (uma garantia quebrada, por exemplo o modo A, o portão de saída, a cadeia de evidência ou um padrão que não é estrito)? Não abra aqui, siga o SECURITY.md.
Este modelo é para desvios que caem nos limites documentados do modo B (paráfrase, tradução, recodificação que ele não conhece). A gente acrescenta ao banco de casos e publica.
-->

**What gets through / O que passa**

**The case, in `bench/propagation_cases.json` format / O caso, no formato do `bench/propagation_cases.json`**

```json
{
  "id": "short-kebab-name",
  "context": [["user", "..."], ["kb", "..."]],
  "argument": "...",
  "expected": "UNTRUSTED",
  "known_failure": true,
  "why": "why mode B can't see it / por que o modo B não enxerga",
  "source": "synthetic"
}
```

**Where it comes from / De onde vem** (incident, paper, benchmark, or `synthetic` / incidente, artigo, benchmark, ou `synthetic`)

**Result of `python -m bench.propagation` with the case added / Resultado com o caso acrescentado**
