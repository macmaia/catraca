# Referência da catraca

*Português (Brasil). [Read in English](reference.md). Voltar para o [README](../README.pt-BR.md).*

Tudo o que o README deixa de fora: como cada peça se comporta, os padrões e como afrouxar.

## O portão

`Gate.decide()` sempre devolve uma `Decision` e nunca levanta exceção. `Gate.check()` faz a mesma coisa, mas levanta `CallDenied` ou `ConfirmationRequired` para tudo que não for ALLOW.

São três vereditos, não dois: `ALLOW`, `DENY` e `REQUIRE_CONFIRMATION`. Uma `Decision` se recusa a funcionar como booleano (`if decision:` levanta `TypeError`), para ninguém ler "precisa de confirmação" como "pode seguir" sem perceber.

`REQUIRE_CONFIRMATION` só aparece num caso bem estreito: o valor tem procedência confiável do começo ao fim e só foi marcado porque o mesmo valor também aparece em conteúdo não confiável (coincidência, não derivação). A decisão leva o valor literal e a origem confiável que o justifica. Se uma política pedir confirmação fora desse caso, o portão transforma o pedido em negação.

### Acompanhando o portão

`Gate(..., on_decision=fn)` chama `fn(decisao)` depois que cada decisão é registrada. Use para métricas ou alertas. Não muda o veredito, e se levantar erro, o erro vai para o log e é ignorado. `gate.counts()` dá as decisões até agora por código de motivo. O portão também escreve no logger `catraca`, em nível ERROR, sempre que está doente e não só estrito: `INTERNAL_ERROR`, `EVIDENCE_UNAVAILABLE` e `INVALID_POLICY_RESULT`. Crie alerta para esses. Um pico deles quer dizer que o portão está negando tudo porque algo quebrou, não porque as chamadas são ruins.

### Retorno da confirmação

`REQUIRE_CONFIRMATION` vem com `decision.confirmation_token`. O token é de uso único, expira (5 min por padrão) e fica preso ao id da chamada, à ferramenta, a quem chamou, ao destino e a uma impressão SHA-256 de todos os valores dos argumentos. Quando a pessoa disser sim, chame `decide`/`check` de novo com a mesma chamada e `confirmation=token`. O portão reavalia tudo contra a janela atual e só libera (motivo `CONFIRMED_BY_USER`) se cair de novo na mesma coincidência, para os mesmos argumentos. Trocou um valor, mudou o destino, reusou o token ou deixou expirar: nega. Resgatar sempre queima o token, casando ou não. `gate.decline(token)` é o botão de "não". O token nunca aparece em `to_dict()` nem no repr, então não vaza para log.

Falha fechado. Qualquer exceção dentro do portão, ou uma política que devolva algo que não seja um `PolicyResult` válido, vira DENY. Só existe um ponto no código que devolve ALLOW.

Cada decisão carrega a própria latência em µs (`elapsed_us`). `python -m bench.latency` mede o p99 numa janela realista.

### Códigos de motivo

Eles são estáveis. A gente acrescenta códigos novos, nunca renomeia.

| Código | Significado |
|---|---|
| `ALLOWED_BY_POLICY` | uma regra da política permitiu a chamada |
| `UNKNOWN_TOOL` | a ferramenta não está na política |
| `UNTRUSTED_ARGUMENT` | um argumento consequente tem procedência não confiável |
| `COINCIDENCE` | o valor é confiável mas também aparece em conteúdo não confiável, então precisa de confirmação |
| `NO_POLICY_MATCH` | uma `Policy` própria não permitiu |
| `INTERNAL_ERROR` | algo quebrou dentro do portão e ele falhou fechado |
| `INVALID_POLICY_RESULT` | a política devolveu algo inutilizável |
| `CONFIRMATION_NOT_ELIGIBLE` | a política pediu confirmação fora do caso de coincidência |
| `CONFIRMED_BY_USER` | a pessoa confirmou o valor literal e a chamada continua batendo |
| `CONFIRMATION_INVALID` | o token é desconhecido, expirou ou já foi usado |
| `CONFIRMATION_MISMATCH` | a chamada não é a que a pessoa confirmou |
| `CALLER_NOT_ALLOWED` | o inquilino ou o usuário não está em `callers` da ferramenta |
| `UNDECLARED_ARGUMENT` | a chamada tem um argumento que a política não declara |
| `ARGUMENT_CONSTRAINT` | um valor não passa em `one_of` ou `pattern` |
| `CONFIDENTIALITY_VIOLATION` | um argumento carrega dado que não pode ir para o escopo exigido |
| `DESTINATION_NOT_ALLOWED` | `destination` não está em `destinations` da ferramenta |
| `EGRESS_NOT_ALLOWED` | um host, endereço ou porta não está na lista de saída permitida |
| `EGRESS_BAD_SCHEME` | uma URL usa um esquema não permitido (só `https` por padrão) |
| `EGRESS_IP_LITERAL` | um destino é um IP cru |
| `EGRESS_PRIVATE_NETWORK` | um destino é localhost, faixa privada, metadados de nuvem ou do tipo `.internal` |
| `EGRESS_UNTRUSTED` | um destino veio de conteúdo não confiável, mesmo com o host permitido |
| `EVIDENCE_UNAVAILABLE` | a decisão não pôde ser gravada no registro de evidência, então a chamada foi negada |

## A política

`DeclarativePolicy` é o avaliador embutido: entra JSON, sai veredito determinístico, sem dependência e sem rede. Ele valida o arquivo inteiro na carga e se recusa a subir com uma mensagem dizendo o que corrigir. Veja `examples/policy.json`.

### Estrito por padrão, afrouxar é de propósito

Você só precisa desta seção para deixar as coisas *mais frouxas*. Omitiu um campo, ficou com o comportamento estrito.

| Campo | Padrão (estrito) | Como afrouxar |
|---|---|---|
| ferramenta fora da lista | negada (`UNKNOWN_TOOL`) | acrescente em `tools` |
| `callers` | obrigatório, não existe "qualquer um" implícito | `{"tenants": "*", "users": "*"}` |
| argumento não declarado | negado (`UNDECLARED_ARGUMENT`) | declare (`{}` mantém os padrões estritos) |
| `integrity` | `"TRUSTED"` | `"STRUCTURED"` ou `"ANY"` |
| `match` | `"whole"`, um único trecho confiável, contíguo | `"partial"` |
| `flow_to` | `["tenant:{tenant}"]`, o dado precisa poder ser lido pelo inquilino de quem chama | outros escopos, por exemplo `["user:{user}"]`, ou `[]` para desligar |
| `destinations` | `[]`, então `destination` precisa vir vazio | liste os permitidos |
| `confirm_on_coincidence` | `false`, coincidência é negada | `true` para perguntar à pessoa |
| `one_of`, `pattern` | nenhum | só acrescentam restrição |
| `type`, `min`, `max` | nenhum | também restringem: `"integer"`, `"number"`, `"boolean"` ou `"date"` (ISO), com limites para números e datas |

As checagens rodam numa ordem fixa e a primeira falha decide: quem chama, argumentos não declarados, destino, `one_of`/`pattern`/`type`, e depois, por argumento, `flow_to` e integridade. `pattern` exige casamento completo.

### Argumentos inofensivos sem a checagem de proveniência

Os padrões estritos negam um `limit=10` que o próprio modelo escolheu, ou uma data calculada a partir de "amanhã", porque nenhum dos dois aparece nas palavras do usuário. A saída tentadora é `"integrity": "ANY"`, que deixa passar qualquer coisa. Um tipo mantém uma caixa apertada:

```json
"limit": {"integrity": "ANY", "type": "integer", "min": 1, "max": 50},
"day":   {"integrity": "ANY", "type": "date", "min": "2026-01-01", "max": "2027-12-31"},
"urgent": {"integrity": "ANY", "type": "boolean"}
```

Números mandados como texto (`"10"`) são aceitos quando convertem sem sobra. O `lint()` avisa sobre número tipado de qualquer origem sem os dois limites. Não faça isso com nada que diga *para onde* ou *para quem* (destinatários, contas, URLs): esses devem continuar `TRUSTED`.

### Lint

`policy.lint()` devolve avisos para revisão e nunca bloqueia nada. Aponta ferramentas que qualquer inquilino pode chamar, argumentos com nome de destino (`to`, `url`, `iban`, `path` e parecidos) que aceitam qualquer integridade ou casamento parcial, e argumentos com `flow_to` desligado. Passando `lint(samples={"ferramenta": [args, ...]})`, por exemplo algumas chamadas registradas em log, ele também confere os argumentos afrouxados pelo valor: e-mails, URLs, IBANs, caminhos de arquivo e telefones.

### Seu próprio avaliador

O `Gate` aceita qualquer coisa que siga o protocolo `Policy` (`relaxed_args(tool)` e `evaluate(request)`), então um motor de política que você já usa pode ficar por trás dele. O portão continua aplicando saída e evidência, diga o avaliador o que disser.

## Saída

A política olha argumento por argumento. O portão de saída faz outra pergunta: para onde esta chamada manda coisas de fato? Ele roda depois da política, em toda chamada, e não depende do motor, então fica atrás de qualquer `Policy` própria também.

Ele extrai destinos de todo argumento, inclusive do texto livre que a política afrouxou: URLs, hosts `www.`, nomes de host soltos (qualquer código de país de duas letras, mais uma lista curada de TLDs genéricos que o CI confere contra a IANA, `Egress(tlds=tlds.load_iana(caminho))` carrega a zona raiz inteira, e terminações com cara de arquivo, como `.sh` ou `.zip`, só contam com caminho ou subdomínio), e-mails, links e imagens em Markdown (inclusive por referência, que foi por onde o EchoLeak saiu), `href`/`src` em HTML, e URLs escondidas dentro de outras URLs (redirecionadores, proxies de pré-visualização, até três níveis). O que não dá para ler até o fim é negado como `EGRESS_NOT_ALLOWED`: uma URL aninhada mais fundo que isso, ou mais de 64 destinos num arg (256 numa chamada), porque são demais para conferir um a um. Links relativos ao esquema (`//host/caminho`) também contam, sozinhos ou em texto livre. Lê o texto como está e de novo depois de decodificar URL, desfazer entidades HTML e "rearmar" endereços desarmados. Os hosts são comparados como um cliente os vê: sem userinfo (`https://acme.com@evil.io` é `evil.io`), barra invertida lida como barra, IDN convertido para punycode (um sósia em cirílico nunca casa com o domínio real), e IPs reconhecidos em notação pontuada, decimal, hexa e octal.

Depois, cada destino é conferido contra as regras da ferramenta e contra a procedência. Um destino copiado de conteúdo recuperado é negado mesmo com o host permitido. A única exceção é uma coincidência pura que a política já está mandando para confirmação.

### Estrito por padrão, afrouxar é de propósito

Sem configuração de saída, qualquer destino nega a chamada. Veja `examples/egress.json`.

| Chave | Padrão (estrito) | Como afrouxar |
|---|---|---|
| `hosts` | `[]` | `"acme.com"`, `"*.acme.com"` (só subdomínios), `"*"` |
| `emails` | `[]` | `"@acme.com"`, `"@*.acme.com"`, `"ana@acme.com"`, `"*"` |
| `schemes` | `["https"]` | acrescente `"http"` e assim por diante |
| `ports` | a do próprio esquema | liste portas extras |
| `ip_literals` | `false` | `true` |
| `private_networks` | `false` | `true` (localhost, RFC 1918, link-local incluindo `169.254.169.254`, `.local`, `.internal`...) |
| `provenance` | `"TRUSTED"` | `"STRUCTURED"` ou `"ANY"` |
| `skip_args` | `[]` | argumentos que não devem ser varridos |

As regras vão por ferramenta em `tools`, com um `default` opcional para as ferramentas fora da lista. Afrouxar a política (por exemplo `"integrity": "STRUCTURED"` em `to`) não afrouxa a saída, e vice-versa. Cada uma precisa ser escrita.


Um destino nomeado como `"smtp"` no `destination` da chamada não é alvo de rede, então só vale a lista `destinations` da política. Se o `destination` for URL, host ou endereço, ele também passa pela saída, com procedência.

## Evidência

Toda decisão, permitida ou negada, vai para o registro de evidência. Se a gravação falhar, a chamada é negada com `EVIDENCE_UNAVAILABLE`. Um portão criado sem registro emite um aviso, e `evidence=None` desliga isso de propósito.

Cada registro tem o suficiente para explicar a decisão sem o dado que estava na chamada: quem (inquilino, e o usuário como digest), ferramenta, veredito, motivo, regra, latência e, para cada argumento, rótulo, regra de resolução, cobertura, origens, se era consequente e se era coincidência, mais um digest com chave e o tamanho do valor. Os alvos de saída guardam tipo, host e integridade, com endereços como digest. A janela aparece como canais e rótulo residual, sem texto. `evidence.replay(registro, política)` roda de novo a etapa da política só com o registro e chega ao mesmo veredito, motivo e regra.

Os registros são encadeados (`seq`, `prev`, `hash`), então uma linha apagada, fora de ordem ou editada no meio reprova no `verify`. Linhas cortadas do começo ou do fim do registro não quebram a cadeia, e reconstruir tudo também não: para isso servem os checkpoints (abaixo). Os arquivos são gravados só por anexação (`O_APPEND`), com fsync a cada escrita, e nascem com permissão 0600. `RotatingJsonlSink(pasta, max_bytes=...)` abre um arquivo novo quando o atual enche e mantém a cadeia atravessando os arquivos.

Os destinos se recusam a gravar através de link simbólico (`O_NOFOLLOW`), então quem tem acesso à pasta de logs não consegue desviar os registros. Se uma gravação falha no meio (disco cheio), o arquivo volta ao tamanho anterior e a chamada é negada. Se o processo morreu no meio de uma gravação, a última linha cortada vai para `<arquivo>.torn` quando o destino abre, e o registro continua começando limpo. Cada destino supõe ser o único a escrever no seu arquivo.

`fsync_every=<segundos>` em qualquer destino troca durabilidade por vazão: cada registro continua sendo escrito antes de a chamada seguir, então um processo que cai não perde nada, mas uma queda de energia pode perder até esse tanto de segundos. O padrão, 0, sincroniza cada registro. Texto livre num registro é limitado a 4.096 caracteres (`[TRUNCATED n chars]`), o que também mantém limitado o custo do mascaramento, seja qual for o valor que um atacante coloque.

A cadeia não pega quem reescreve o log inteiro e refaz a cadeia. Para isso, tire de tempos em tempos um checkpoint com `log.checkpoint(chave_de_ancora)` e guarde em outro lugar (um ticket, um bucket com trava de objeto, um carimbo de tempo assinado). `verify(..., anchor=cp, anchor_key=...)` prova que o log ainda tem aquele registro exato. Um checkpoint sem `anchor_key` é recusado, porque quem reescreveu o log pode ter escrito o checkpoint também. `trust_unsigned_anchor=True` aceita quando ele veio de um lugar em que só você grava.

O replay funciona com usuário e inquilino pseudonimizados: quem chama é checado primeiro, então o motivo registrado diz como foi essa checagem, e regras que citam usuários específicos são reproduzidas sem os ids reais. Vale ser claro: na checagem de quem chama (e num destino reduzido ao host) o replay lê o resultado do registro em vez de recalcular, então bate por construção. As checagens de integridade, confidencialidade e saída são recalculadas. Privacidade, retenção e o que o registro prova estão em [audit-and-privacy.md](audit-and-privacy.md).

| Ajuste | Padrão (estrito) | Como afrouxar |
|---|---|---|
| valores dos argumentos | nunca gravados, só um digest com chave e o tamanho | `include_preview=True` grava uma prévia mascarada |
| ids de usuário e de inquilino | digest com chave, e o mesmo para nomes `tenant:`/`user:` dentro dos rótulos | `pseudonymise_users=False` |
| `destination` | só esquema, host e porta, o resto é descartado | `include_preview=True` |
| chave do digest | aleatória por processo | passe `key=` (16 bytes ou mais, fora do log) para correlacionar entre execuções |
| mascaramento de texto livre (`detail`, valores da janela) | limpador embutido: e-mails, CPF e CNPJ (com dígito verificador conferido), RG, CEP, telefones, IPv4 e IPv6, IBANs, cartões (Luhn), chaves de API, JWTs, tokens bearer, pares do tipo `password=`, e qualquer outra sequência de 10 ou mais dígitos. **Não** pega nomes, endereços nem outros dados pessoais em texto livre | `redactor=` com uma ferramenta de PII de verdade, por exemplo `tarja_redactor()` (experimental) |

```
python -m catraca.evidence verify decisions.jsonl
python -m catraca.evidence verify logs/decisions-*.jsonl --anchor cp.json --anchor-key-env CATRACA_ANCHOR_KEY
python -m catraca.evidence stats  decisions.jsonl   # inclui a taxa de coincidência
python -m catraca.evidence export --format ecs decisions.jsonl   # ou cef
```

O `stats` informa a `coincidence_rate`, a fração das decisões bloqueadas ou mandadas para confirmação só por coincidência. Se estiver alta, a política está escrita errada, não o mundo. É métrica de produto, não de segurança.

## Modo A, o plano selado

```python
from catraca.plan import Plan, PlanRunner, Schema, Step, ask, lit, ref

plan = Plan([
    Step("read_ticket", {"ticket_id": lit("7781")}),
    Step("send_email", {"to": lit("ana@acme.com.br"),
                        "body": ask("Resuma o ticket", ref(0, "text"), Schema.text(300))}),
], policy=policy, request="Resuma o ticket 7781 e mande para mim por e-mail")

runner = PlanRunner(Gate(None, policy, egress=egress, evidence=log), tools, caller=caller,
                    seal_key=key, quarantine=q_llm, approve=ask_the_person)
result = runner.run(plan.seal(key))
```

* Os argumentos são `lit(...)` (fixo agora, confiável), `ref(passo, *caminho)` (saída de um passo anterior, não confiável), `ask(instrução, origem, schema)` (um valor extraído de dado não confiável pela quarentena, um modelo sem ferramentas cuja resposta precisa caber no schema) ou `confirm(...)` (uma pessoa aprova o valor literal, e aí ele conta como confiável).
* Argumentos consequentes (tudo o que a política não afrouxa) precisam ser `lit` ou `confirm`. Então os destinos ficam fixos antes de qualquer conteúdo não confiável ser lido, ou uma pessoa assina. Um plano que quebra isso não é montado.
* `seal(chave)` congela o plano (codificação canônica, SHA-256, HMAC). O executor decodifica a própria cópia, confere o selo antes de começar e antes de cada passo, e não tem caminho de volta para o planejador.
* Todo passo continua passando pelo portão (política, saída, evidência), com rótulos fixados nas bordas. Então um endereço que a quarentena foi enganada a escrever num corpo é barrado pela saída.
* `plan_with(planejador, pedido, policy=..., tools=...)` pede o plano a um modelo planejador, que só vê o pedido e a lista de ferramentas.

Limites: os planos são lineares, sem laço nem desvio que dependa de dado. Canais laterais (quantos passos rodaram, tempo, qual passo falhou) não são cobertos, como no CaMeL. O custo em utilidade no AgentDojo ainda não foi medido.

## Adaptadores

| Adaptador | Onde | Observações |
|---|---|---|
| Decorador Python | `catraca.adapters.python.guarded` | `guarded(gate, caller=fn, tool=None, destination=None, approve=None)`. `caller` é uma função sem argumentos que devolve o `Caller` da requisição atual, chamada a cada chamada. `approve(decisao)` mostra `decisao.confirmation` à pessoa e devolve `True` só com um sim explícito (síncrona ou assíncrona). Sem `approve`, uma confirmação levanta `ConfirmationRequired`. Os argumentos são associados pelo nome, com os padrões, e os argumentos já fixados num `functools.partial` também são conferidos. Funções com `*args`/`**kwargs` são recusadas. Só executa a função com ALLOW, síncrona ou assíncrona |
| Middleware de servidor MCP | `catraca.adapters.mcp.catraca_middleware` | `async (ctx, call_next)`. O SDK marca esse gancho como provisório. O servidor não vê o contexto do cliente, então os argumentos são UNTRUSTED, a não ser que o cliente assine os rótulos (`sign_labels`, conferido com `label_key=`, preso à ferramenta, aos valores e a uma janela de 5 minutos) ou você passe `trust_client=True`. As recusas usam o erro do próprio SDK, código -32001 |

Cada um tem um exemplo executável em `examples/`, e o CI roda todos (o do MCP contra o SDK de verdade).

## Modelo de rótulos

Integridade: `TRUSTED < STRUCTURED < UNTRUSTED`, e a junção pega o máximo.

Confidencialidade é um conjunto de escopos de leitura, e a junção é a interseção. Então aqui o conjunto **menor** é o mais restritivo. `PUBLIC` (`"*"`) é o topo e o elemento neutro, `{"*"} ∩ X = X`. `"*"` nunca é escopo literal. O conjunto vazio é o fundo e bloqueia qualquer saída.

## Regras de resolução

| Regra | Quando | Rótulo |
|---|---|---|
| EXACT | a forma canônica é igual a um trecho inteiro | junção dos trechos |
| SUBSTRING | o argumento inteiro é coberto por janelas vindas de trechos (8 caracteres normalizados por padrão) | junção dos trechos |
| PARTIAL | parte está coberta, parte não | mapa de cobertura: segmentos cobertos herdam a origem, os descobertos ficam com o residual |
| CONSERVATIVE | nada casou | residual, a junção de tudo o que está na janela, nos dois eixos |
| NO_FULL_MATCH | posição consequente sem casamento inteiro e contíguo com um único trecho confiável | UNTRUSTED |

Nada abaixo do limiar conta como cobertura. As variantes decodificadas só acrescentam origem, nunca concedem confiança. O que é tratado hoje: caixa, espaço, pontuação, acento, caracteres invisíveis, homóglifos de largura total, cirílicos e gregos, leetspeak (dobrado na forma canônica, então sai de graça), percent-encoding de URL, entidades HTML, escapes `\u`/`\x`, base64, punycode (`xn--`), endereços "desarmados" (`[at]`, `[dot]`, `hxxp`) e rot13.

### Todo argumento é consequente, a não ser que você diga o contrário

A regra de casamento total é o padrão para todo argumento. A política lista os que podem ser mais frouxos (`"match": "partial"` ou `"integrity": "ANY"`). Então esquecer algo deixa mais estrito, nunca mais frouxo. O lint (na seção da política, acima) aponta argumentos com cara de destino que foram afrouxados.

O que "casamento total" quer dizer exatamente: o valor tem que aparecer num trecho confiável como tokens inteiros. Caixa e os espaços que as pessoas usam para agrupar dígitos (um IBAN em blocos de quatro) são dobrados. Nada além disso: a pontuação do próprio valor tem que estar lá como foi digitada (`../data` não é `/data`), e um valor que muda com a normalização Unicode NFKC (letras de largura cheia, ligaduras) nunca vira confiável, porque a ferramenta receberia uma string que o usuário não digitou. Dentro de contêineres, chaves de dicionário com cara de dado (dígitos, `@`, pontos) são resolvidas como valores, nomes de campo simples (`status`, `first_name`) contam como estrutura, e uma lista ou dicionário vazio é resolvido como string vazia.

## Janela de contexto

O registro acompanha a janela de contexto do modelo, não o turno. Invariante: existe entrada para todo trecho que ainda está no contexto.

* `new_turn()` só avança o contador. Não esquece nada.
* `forget(id, reason=...)` é ato explícito e fica registrado em `forget_log`. Na dúvida sobre o que saiu do contexto, não esqueça.
* `summarise(text, replaces=[ids])` registra o resumo com a junção da janela inteira e só depois esquece os originais. Resumo de janela contaminada nasce UNTRUSTED.
* `export_state(key=...)` e `ContextRegistry.from_state(channels, state, key=...)` levam a janela de um processo para outro, por exemplo para guardar junto do checkpoint do seu framework de agentes. O estado contém os textos dos trechos, então guarde como a conversa. Sem a chave ele é recusado, a não ser com `trust_unsigned=True`, porque quem edita o estado poderia rotular um trecho não confiável como confiável.

## Threads e escala

Todo método público do `ContextRegistry` pega um lock, e o portão resolve a chamada inteira mais o resumo da janela num único retrato, então dá para compartilhar entre threads e tarefas asyncio. Use um registro por conversa, nunca um por processo: toda decisão pega o lock do registro, então um registro compartilhado põe todo o tráfego em fila (cerca de 1.200 decisões por segundo num núcleo, nas nossas medições). Sozinho, não é compartilhado entre processos: use `export_state`/`from_state` para o registro e um `PendingBackend` compartilhado para as confirmações (abaixo).

Código assíncrono deve chamar `await gate.adecide(...)` (ou `acheck`), que roda a decisão numa thread para um arg longo não travar o event loop. O decorador assíncrono e o middleware MCP já fazem isso.

Os tokens de confirmação ficam em memória por padrão. Com vários workers, passe `ConfirmationStore(backend=...)` com qualquer coisa que tenha `put(token, record, ttl_seconds)`, `take(token)` e `drop(token)`, em que `take` lê e apaga num passo atômico. No Redis é `SET token record EX ttl`, `GETDEL token` e `DEL token`. O relógio passa a ser o de parede quando há backend.

Numa janela de ~100 mil tokens (40 docs, 565 mil caracteres, `python -m bench.scale`): uns 39 MiB no registro, ~38 ms para anotar cada doc, e `decide` com p50 ≈ 0,3 a 0,35 ms / p99 ≈ 0,6 a 0,8 ms para argumento de destino. Um corpo de texto livre de 400 palavras custa mais, p50 ≈ 4,4 ms / p99 ≈ 6,6 ms, porque cada caractere ganha uma posição no mapa de cobertura. São os números da máquina de referência do [BENCHMARK.md](../BENCHMARK.md), então rode na sua máquina.
