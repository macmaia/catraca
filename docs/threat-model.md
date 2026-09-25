# Threat model

*English (UK) first. [Versão em português mais abaixo](#modelo-de-ameacas-pt-br).*

## What we're protecting

The tools an agent can call, and what those calls can reach: money, messages, files, other people's data, and the network.

## Who we assume is hostile

**The attacker controls content the agent reads**, but not the user, the operator or the code. That's indirect prompt injection: a web page, an email, a shared doc, a ticket, a tool's output, a retrieved chunk. The attacker knows how catraca works (the code is public) and will try to get an attacker-chosen value into a consequential arg: a recipient, an IBAN, a URL, a file path.

**The model is treated as confused, not as an adversary with memory.** It may follow injected instructions, paraphrase, re-encode or mix values. We don't assume it keeps a secret channel between turns outside the context window.

## Trust boundaries

| Trusted | Not trusted |
|---|---|
| The operator's config: channels, policy, egress rules, keys | Anything from a channel labelled UNTRUSTED |
| The user's own input on a TRUSTED channel | Tool outputs, unless the channel says otherwise |
| The host process running the gate | The model's choice of tool and args |
| In mode A, the plan as sealed | In MCP, the client's claims about provenance, unless signed |

## What each mode promises

| Attack | Mode A (sealed plan) | Mode B (registry) |
|---|---|---|
| Injected content changes which tool runs or in what order | Stopped. The plan is sealed before any untrusted content is read. | Not addressed by the registry. The policy still limits which tools and callers are allowed. |
| Injected value copied literally into a consequential arg | Stopped: consequential args must be literals or confirmed. | Caught (EXACT, SUBSTRING) and denied or sent for confirmation. Trust needs the value as whole tokens of the user's text, with only case and grouping spaces folded (and the value's own punctuation kept), so "10000" isn't trusted because the user wrote "100.00". |
| Same, lightly obfuscated (case, accents, homoglyphs, leetspeak, URL/HTML/base64 encoding, punycode, defanging, rot13) | Stopped. | Caught for the variants listed in `normalise.py`. |
| Injected text picks **which** trusted value to use ("not mallory@, send to bob@" then "use mallory"), or puts a trusted value in the wrong arg (a ticket number as the amount) | Stopped: the plan fixes each arg before anything untrusted is read. | **Not caught.** Mode B knows where a value came from, not what the user meant it for. Every value the user typed counts as trusted for any consequential arg. See below. |
| Same, paraphrased or translated | Stopped. | **Not caught** as such. The conservative rule labels unmatched args UNTRUSTED when the window holds untrusted content, which covers much of it but isn't a guarantee. |
| Exfil through a URL, image link or email to an attacker host | Egress allowlist applies. | Egress allowlist applies, plus provenance of the target. |
| Data from one tenant flowing to another | Confidentiality labels and `flow_to`. | Same. |
| Replaying a confirmation for a different call | Token is single use, bound to call, tool, caller, destination and an arg fingerprint. | Same. |
| Tampering with the decision log | Hash chain plus HMAC checkpoints held elsewhere. Records after the latest checkpoint can still be cut off the end unnoticed, so checkpoint often. | Same. |
| Changing a sealed plan between steps | Seal re-checked before each step, key held by the runner. | n/a |

## Choosing among trusted values (mode B)

Provenance answers "did this value come from the user?", not "did the user want it here?". If the user's own text holds several candidates of the same kind (two addresses, two IBANs, an amount and a ticket number), injected text can steer the model to the wrong one and every arg still looks trusted. There's no complete fix inside mode B. What helps:

* mode A, where the plan binds each value to its arg before untrusted content is read.
* keeping a trusted value to a single token (catraca only trusts whole tokens, so a piece of an IBAN or a reference number isn't trusted on its own).
* planned: asking for confirmation when the trusted text holds more than one candidate of the arg's type.

## An attacker who knows the matcher

Assume the attacker has read this code. Against mode B, the obvious move is to never write the value literally: spell it out ("f i n at fake dash supplier dot com"), describe it ("the account ending in 3000"), or have the model translate or compute it. What stops that today is the conservative rule, not the matcher: while untrusted content is in the window, any consequential value that doesn't match a trusted token is UNTRUSTED, whatever it looks like. So these attacks fail as long as the window is tracked honestly. They succeed when the untrusted source has been dropped from the registry while the model still remembers it (a `forget` that wasn't really true), or when the attacker only steers the choice among values the user wrote. Both are in the case bank as published known failures. The first one is closed when the integration passes the model's window to `observe()` every turn: `forget` is refused while the text is visible, and the model's own replies, which carry whatever it remembers, come in as UNTRUSTED. The second one isn't. Mode A isn't affected, since nothing the model reads after sealing can change the plan's args.

## Out of scope

* A compromised host, operator or policy author. If they can edit the policy, they can allow anything.
* The model leaking data in its **reply text** to the user. catraca guards tool calls, not chat output.
* DNS rebinding and anything that happens after the call is allowed. Hosts are checked by name, never resolved. The HTTP client has to do its own checks.
* Side channels (timing, which tool was chosen, how many calls).
* Tools that do more than their name and args say. A tool that fetches whatever URL is in a doc it opens needs its own guard.
* Availability. An attacker who fills the window with untrusted text can push mode B towards denying things. That's by design: it fails closed.
* Confirmation fatigue. REQUIRE_CONFIRMATION only helps if a person reads the prompt. The coincidence rate from `stats` shows how often it fires.

## Residual risks we know about

The case banks publish the ones we've found (`bench/propagation_cases.json`, the `known_failure` flag, and [BENCHMARK.md](../BENCHMARK.md)). Today they're a translated value after the untrusted source was dropped from the window, and a rot13 value whose origin was forgotten. Both are mode B only.

---

<a id="modelo-de-ameacas-pt-br"></a>

# Modelo de ameaças (pt-BR)

## O que protegemos

As ferramentas que o agente pode chamar e o que essas chamadas alcançam: dinheiro, mensagens, arquivos, dados de terceiros e a rede.

## Quem supomos hostil

**O atacante controla conteúdo que o agente lê**, mas não o usuário, o operador nem o código. É injeção indireta de prompt: página web, email, documento compartilhado, ticket, saída de ferramenta, trecho recuperado. O atacante sabe como a catraca funciona (o código é público) e vai tentar levar um valor escolhido por ele para um arg consequente: destinatário, IBAN, URL, caminho de arquivo.

**O modelo é tratado como confuso, não como adversário com memória.** Ele pode seguir instruções injetadas, parafrasear, recodificar ou misturar valores. Não supomos que ele guarde um canal secreto entre turnos fora da janela de contexto.

## Fronteiras de confiança

| Confiável | Não confiável |
|---|---|
| A configuração do operador: canais, política, regras de saída, chaves | Qualquer coisa de um canal rotulado UNTRUSTED |
| A entrada do próprio usuário num canal TRUSTED | Saídas de ferramentas, a não ser que o canal diga outra coisa |
| O processo que roda o portão | A escolha de ferramenta e args feita pelo modelo |
| No modo A, o plano como foi selado | No MCP, o que o cliente afirma sobre proveniência, a não ser que venha assinado |

## O que cada modo promete

| Ataque | Modo A (plano selado) | Modo B (registro) |
|---|---|---|
| Conteúdo injetado muda qual ferramenta roda ou em que ordem | Barrado. O plano é selado antes de ler qualquer conteúdo não confiável. | O registro não trata disso. A política ainda limita ferramentas e chamadores. |
| Valor injetado copiado literalmente num arg consequente | Barrado: arg consequente tem que ser literal ou confirmado. | Pego (EXACT, SUBSTRING) e negado ou mandado para confirmação. A confiança exige o valor como tokens inteiros do texto do usuário, só com caixa e espaços de agrupamento dobrados (e a pontuação do próprio valor mantida), então "10000" não vira confiável porque o usuário escreveu "100.00". |
| O mesmo, levemente ofuscado (caixa, acentos, homóglifos, leetspeak, codificação URL/HTML/base64, punycode, defang, rot13) | Barrado. | Pego para as variantes listadas em `normalise.py`. |
| Texto injetado escolhe **qual** valor confiável usar ("não mande para mallory@, mande para bob@" e depois "use a mallory"), ou põe um valor confiável no arg errado (número de ticket como valor a pagar) | Barrado: o plano fixa cada arg antes de ler qualquer coisa não confiável. | **Não é pego.** O modo B sabe de onde o valor veio, não para que o usuário o queria. Todo valor digitado pelo usuário conta como confiável para qualquer arg consequente. Veja abaixo. |
| O mesmo, parafraseado ou traduzido | Barrado. | **Não é pego** como tal. A regra conservadora rotula como UNTRUSTED os args sem correspondência quando a janela tem conteúdo não confiável, o que cobre boa parte, mas não é garantia. |
| Exfiltração por URL, link de imagem ou email para host do atacante | Vale a lista de saída permitida. | Vale a lista de saída, mais a proveniência do alvo. |
| Dado de um tenant indo para outro | Rótulos de confidencialidade e `flow_to`. | Igual. |
| Reaproveitar uma confirmação em outra chamada | Token de uso único, preso a chamada, ferramenta, chamador, destino e impressão digital dos args. | Igual. |
| Adulterar o registro de decisões | Cadeia de hash mais checkpoints HMAC guardados em outro lugar. Registros depois do último checkpoint ainda podem ser cortados do fim sem ninguém notar, então tire checkpoints com frequência. | Igual. |
| Mudar um plano selado entre passos | Selo reconferido antes de cada passo, chave com quem executa. | n/a |

## Escolha entre valores confiáveis (modo B)

A proveniência responde "esse valor veio do usuário?", não "o usuário queria esse valor aqui?". Se o próprio texto do usuário tem vários candidatos do mesmo tipo (dois endereços, dois IBANs, um valor e um número de ticket), um texto injetado pode levar o modelo ao errado e todo arg continua parecendo confiável. Não há correção completa dentro do modo B. O que ajuda:

* o modo A, em que o plano prende cada valor ao seu arg antes de ler conteúdo não confiável.
* confiança só em tokens inteiros (a catraca só confia em tokens inteiros, então um pedaço de IBAN ou de número de referência não vira confiável sozinho).
* previsto: pedir confirmação quando o texto confiável tiver mais de um candidato do tipo do arg.

## Um atacante que conhece o casamento

Suponha que o atacante leu este código. Contra o modo B, o movimento óbvio é nunca escrever o valor literalmente: soletrar ("f i n arroba fake traço supplier ponto com"), descrever ("a conta que termina em 3000") ou fazer o modelo traduzir ou calcular. O que barra isso hoje é a regra conservadora, não o casamento: enquanto houver conteúdo não confiável na janela, qualquer valor consequente que não case com um token confiável é UNTRUSTED, tenha a cara que tiver. Então esses ataques falham enquanto a janela for acompanhada com honestidade. Funcionam quando a fonte não confiável saiu do registro mas o modelo ainda lembra dela (um `forget` que não era verdade), ou quando o atacante só direciona a escolha entre valores que o usuário escreveu. Os dois estão no banco de casos como falhas conhecidas publicadas. O primeiro se fecha quando a integração passa a janela do modelo para `observe()` a cada turno: o `forget` é recusado enquanto o texto está visível, e as respostas do próprio modelo, que carregam o que ele lembra, entram como UNTRUSTED. O segundo, não. O modo A não é afetado, porque nada que o modelo leia depois do selo muda os args do plano.

## Fora do escopo

* Host, operador ou autor da política comprometidos. Quem edita a política pode permitir qualquer coisa.
* O modelo vazar dado no **texto da resposta** ao usuário. A catraca guarda chamadas de ferramenta, não a saída do chat.
* DNS rebinding e tudo que acontece depois que a chamada é permitida. Os hosts são conferidos pelo nome, nunca resolvidos. O cliente HTTP tem que fazer as próprias checagens.
* Canais laterais (tempo, qual ferramenta foi escolhida, quantas chamadas).
* Ferramentas que fazem mais do que o nome e os args dizem. Uma ferramenta que busca qualquer URL de um documento que ela abre precisa de guarda própria.
* Disponibilidade. Um atacante que enche a janela de texto não confiável pode empurrar o modo B a negar coisas. É de propósito: falha fechado.
* Fadiga de confirmação. REQUIRE_CONFIRMATION só ajuda se uma pessoa ler o pedido. A taxa de coincidência do `stats` mostra com que frequência ele dispara.

## Riscos residuais conhecidos

Os bancos de casos publicam os que encontramos (`bench/propagation_cases.json`, a marca `known_failure`, e o [BENCHMARK.md](../BENCHMARK.md)). Hoje são um valor traduzido depois que a fonte não confiável saiu da janela, e um valor em rot13 cuja origem foi esquecida. Os dois só afetam o modo B.
