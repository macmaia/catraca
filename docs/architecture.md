# Architecture

*English (UK) first. [Versão em português mais abaixo](#arquitetura-pt-br).*

catraca sits between an agent and its tools. Every tool call goes through one function, `Gate.decide`, which answers ALLOW, DENY or REQUIRE_CONFIRMATION and writes down why. Nothing in the core needs the network or a third-party package.

```
             trusted input          untrusted content (docs, mail, web, tool output)
                  |                              |
                  v                              v
   mode A:   PlanRunner (sealed plan)     mode B:   ContextRegistry (labels per snippet)
                  |  EdgeLabel per arg            |  Resolution per arg
                  +---------------+---------------+
                                  v
                           Gate.decide(tool, args, caller)
                                  |
      1. confirmation token (if any): single use, bound to the call
      2. Policy.evaluate: caller, declared args, integrity, confidentiality, constraints
      3. Egress: targets pulled out of the args, checked by name, never resolved
      4. EvidenceLog.record: hash-chained, redacted. If it can't write, DENY
                                  |
                                  v
                    ALLOW  |  DENY  |  REQUIRE_CONFIRMATION
```

## The pieces

| Module | What it does |
|---|---|
| `labels.py` | The label lattice. Integrity TRUSTED < STRUCTURED < UNTRUSTED, confidentiality as a set of scopes (join by intersection, `"*"` is public). |
| `channels.py` | Maps each input channel (user, kb, email...) to a starting label. Loaded from JSON. |
| `normalise.py` | NFKC, homoglyphs, accents, case, leetspeak, plus the decoded variants (URL, HTML, escapes, base64, punycode, refang, rot13). |
| `registry.py` | Mode B. Holds labelled snippets for the current context window and resolves each arg to a label with a rule (EXACT, SUBSTRING, PARTIAL, CONSERVATIVE, NO_FULL_MATCH). |
| `policy.py` | The declarative policy in JSON. Strict defaults, `lint()`, pluggable checks for replay. |
| `egress.py`, `tlds.py` | Pulls URLs, hosts and emails out of args (redirectors, IDN, IP forms included) and checks them against an allowlist. |
| `gate.py`, `confirmations.py` | The single decision point. Fails closed, and a `Decision` can't be used as a bool by mistake. |
| `evidence.py` | Hash-chained JSONL records, HMAC digests of values, pseudonymised users, checkpoints, `verify`, `replay`, `stats`, ECS and CEF export. |
| `plan.py` | Mode A. Plans built from trusted input, sealed with HMAC, re-checked before every step, run through the same gate. |
| `adapters/python.py`, `adapters/mcp.py` | Thin wrappers: a decorator for plain functions and middleware for MCP servers. |

## Design rules

1. **One ALLOW.** There's exactly one place in `gate.py` that returns ALLOW. Every exception on the way turns into DENY with `INTERNAL_ERROR`.
2. **Strict by default.** Every arg is consequential unless the policy relaxes it. Undeclared args are denied. Egress allows nothing until you list it. No evidence sink means a warning at construction and, if a sink fails later, DENY.
3. **No taint tracking in Python.** catraca never instruments the interpreter. Mode B infers provenance from text, mode A carries it structurally.
4. **Offline.** The gate never resolves a name or calls out.
5. **Stable reason codes.** `Reason` values are an API. They get added, never renamed.

## Where mode A and mode B meet

Both end at `Gate.decide`. Mode B passes the registry's resolution for each arg. Mode A passes `labels=`, an `EdgeLabel` per arg fixed where the value entered the plan (a literal from the user, a ref to a previous step's output, a value asked of a quarantined reader, or a confirmation). The policy, egress and evidence steps don't care which mode they're in, and the record says which it was.

See [threat-model.md](threat-model.md) for what this is meant to stop and what it isn't.

---

<a id="arquitetura-pt-br"></a>

# Arquitetura (pt-BR)

A catraca fica entre o agente e as ferramentas dele. Toda chamada passa por uma função só, `Gate.decide`, que responde ALLOW, DENY ou REQUIRE_CONFIRMATION e registra o porquê. Nada no núcleo precisa de rede nem de pacote de terceiros.

O diagrama acima vale para as duas línguas. A ordem dentro do portão é:

1. token de confirmação (se houver): uso único, preso à chamada.
2. `Policy.evaluate`: chamador, args declarados, integridade, confidencialidade, restrições.
3. saída (egress): alvos extraídos dos args, conferidos pelo nome, nunca resolvidos.
4. `EvidenceLog.record`: encadeado por hash, com tarja. Se não conseguir gravar, DENY.

## As peças

| Módulo | O que faz |
|---|---|
| `labels.py` | O reticulado de rótulos. Integridade TRUSTED < STRUCTURED < UNTRUSTED, confidencialidade como conjunto de escopos (junção por interseção, `"*"` é público). |
| `channels.py` | Associa cada canal de entrada (usuário, kb, email...) a um rótulo inicial. Carregado de JSON. |
| `normalise.py` | NFKC, homóglifos, acentos, caixa, leetspeak, mais as variantes decodificadas (URL, HTML, escapes, base64, punycode, refang, rot13). |
| `registry.py` | Modo B. Guarda trechos rotulados da janela de contexto atual e resolve cada arg para um rótulo com uma regra (EXACT, SUBSTRING, PARTIAL, CONSERVATIVE, NO_FULL_MATCH). |
| `policy.py` | A política declarativa em JSON. Padrões estritos, `lint()`, verificações plugáveis para o replay. |
| `egress.py`, `tlds.py` | Extrai URLs, hosts e emails dos args (redirecionadores, IDN e formas de IP incluídos) e confere contra uma lista de permitidos. |
| `gate.py`, `confirmations.py` | O ponto único de decisão. Falha fechado, e um `Decision` não pode ser usado como bool por engano. |
| `evidence.py` | Registros JSONL encadeados por hash, digests HMAC dos valores, usuários pseudonimizados, checkpoints, `verify`, `replay`, `stats`, exportação ECS e CEF. |
| `plan.py` | Modo A. Planos feitos só de entrada confiável, selados com HMAC, reconferidos antes de cada passo, rodados pelo mesmo portão. |
| `adapters/python.py`, `adapters/mcp.py` | Invólucros finos: um decorador para funções comuns e um middleware para servidores MCP. |

## Regras de projeto

1. **Um ALLOW só.** Existe exatamente um lugar em `gate.py` que devolve ALLOW. Qualquer exceção no caminho vira DENY com `INTERNAL_ERROR`.
2. **Estrito por padrão.** Todo arg é consequente a não ser que a política afrouxe. Arg não declarado é negado. A saída não permite nada até você listar. Sem destino de evidência, há aviso na construção e, se o destino falhar depois, DENY.
3. **Sem rastreio de taint no Python.** A catraca nunca instrumenta o interpretador. O modo B infere a proveniência pelo texto, o modo A carrega a proveniência na estrutura.
4. **Sem rede.** O portão nunca resolve nome nem faz chamada externa.
5. **Códigos de motivo estáveis.** Os valores de `Reason` são API. Ganham itens novos, nunca mudam de nome.

## Onde o modo A e o modo B se encontram

Os dois terminam em `Gate.decide`. O modo B passa a resolução do registro para cada arg. O modo A passa `labels=`, um `EdgeLabel` por arg, fixado onde o valor entrou no plano (literal do usuário, referência à saída de um passo anterior, valor pedido a um leitor em quarentena, ou confirmação). Política, saída e evidência não se importam com o modo, e o registro diz qual foi.

Veja [threat-model.md](threat-model.md) para o que isso pretende barrar e o que não pretende.
