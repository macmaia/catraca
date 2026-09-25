# Design decisions

*English (UK) first. [Versão em português mais abaixo](#decisoes-de-desenho-pt-br).*

The repo's history starts at the first public release, so this page is where the reasoning lives. Each entry says what was decided, why, and what it costs. New decisions get a new entry here in the same pull request that makes them.

## 1. Fail closed, always

Any error inside the gate, a policy that returns something malformed, a log that can't be written, a destination that can't be read to the end: the answer is DENY with a reason code, never ALLOW. **Why:** a guard that allows on error is a guard an attacker can switch off by causing errors. **Cost:** outages look like denials, so the gate logs at ERROR and exposes `counts()` to tell the two apart.

## 2. The safe setting is the default

Every default is the strictest one: every arg must come from the user, no destination is allowed, coincidences are denied, digests use a random key, a gate without an evidence log warns. Loosening is always explicit and visible in config. **Why:** people copy the first example that works. **Cost:** a first integration is denied more than people expect, which is why the README explains each denial and how to loosen it on purpose.

## 3. No runtime dependencies, no model in the loop

The core is standard library only, and no decision calls a model. **Why:** a security check should be deterministic, auditable and cheap enough to run on every call, and a dependency is one more thing to trust. **Cost:** no fuzzy matching, so paraphrase and translation aren't caught by the matcher (see decision 5).

## 4. Two modes with different promises

Mode A (sealed plan) gives a structural guarantee: nothing read after sealing changes which tools run or their args. Mode B (registry) works with an unmodified agent and infers where each value came from. **Why:** mode A is the right answer when the task can be planned up front, mode B is what most existing agents can adopt today. **Cost:** two things to document, and the README has to be clear that mode B is a strong filter, not a guarantee.

## 5. Trust only whole tokens, and let the residual do the rest

In mode B, a consequential value is trusted only if it appears as whole tokens of one trusted snippet, with case, width and grouping spaces folded, and grouping only for mostly numeric values. Anything that doesn't match, while untrusted content is in the window, gets the join of the window, which is untrusted. **Why:** substring or fuzzy matching let "10000" be trusted from "100.00" and a piece of an IBAN be trusted on its own. The conservative residual catches spelled-out and paraphrased attacker values without having to recognise them. **Cost:** false positives when the model reformats or computes a value (6 of the 26 calls in the benign bank). Typed args with bounds are the fix for harmless args.

## 6. A coincidence is its own verdict

When a trusted value also appears in untrusted content, the gate doesn't pretend to know which one the model used. It denies by default, or asks the person with a single-use token bound to the exact call. **Why:** guessing either way is wrong half the time. **Cost:** the confirmation path needs work in the app, so measure the coincidence rate before building it.

## 7. Destinations are read from every arg and checked by name

Egress looks at every arg, including free text, and unwraps redirectors. Hosts are compared by name, never resolved. Anything it can't read to the end (nested deeper than three levels, more than 64 destinations in one arg) is denied. **Why:** exfiltration usually hides in a body or a link, not in a field called `url`. Resolving names would make the decision depend on DNS, which the attacker may control. **Cost:** DNS rebinding and what the HTTP client does afterwards are out of scope, and long link lists are refused.

## 8. The log proves decisions without holding the data

Records keep keyed digests of values and pseudonymised users and tenants, destinations cut to scheme and host, and free text through a redactor. Records are hash-chained, and checkpoints signed with a separate key are kept elsewhere. **Why:** an audit log full of personal data becomes the next thing to protect. **Cost:** the log is still pseudonymised personal data (the key links it back), and records after the last checkpoint can be cut off the end, so checkpoints have to run on a schedule.

## 9. Confirmation tokens are single use and bound to the call

A token only works once, and only for the same tool, caller, destination and a fingerprint of the args. **Why:** otherwise a yes to one call can be replayed for another. **Cost:** a shared store is needed when several workers serve the same conversation (`PendingBackend`).

## 10. The benchmark is published with its failures

Every figure comes from one command anyone can run, known failures are listed, and the AgentDojo bank is labelled as circular by construction. **Why:** a security claim nobody can check isn't worth much. **Cost:** the numbers look less impressive than a curated table would.


## 11. The registry checks the window instead of trusting it

Mode B depends on the registry knowing what's in the model's context. `observe()` compares the two every turn: text nobody annotated is added as UNTRUSTED, and `forget` is refused while the text is still visible. **Why:** an integration that misses a source or drops one too early used to weaken mode B without a sound. Now the mistake makes it stricter. **Cost:** the integration has to pass the window's texts each turn and annotate text exactly as the model gets it, the system prompt included.

## 12. Derived values count only when they name the same thing

Two derived forms are trusted: the host of a URL the user wrote, and a phone number with the same digits re-punctuated. A computed date, a sum or a translation isn't, even though that leaves false positives. **Why:** a host or a re-spaced number points at the same place the user named. A computed value is exactly what an attacker would steer. **Cost:** 6 of the 26 calls in the benign bank are still flagged.

## 13. Relaxed args skip the work when it can't change the verdict

An arg that accepts any integrity, where even the join of the whole window may flow to the caller, gets the window's label without being resolved piece by piece. **Why:** long free-text bodies were the slowest thing the gate did, and the answer was known in advance. The window's label is never looser than what resolving would find, and a test compares both paths. **Cost:** the evidence record shows such an arg as CONSERVATIVE with the window's label, not its coverage.

---

<a id="decisoes-de-desenho-pt-br"></a>

# Decisões de desenho (pt-BR)

O histórico do repositório começa no primeiro lançamento público, então é nesta página que fica o raciocínio. Cada item diz o que foi decidido, por quê, e o que custa. Decisões novas entram aqui no mesmo pull request que as faz.

## 1. Falhar fechado, sempre

Qualquer erro dentro do portão, uma política que devolve algo malformado, um registro que não pode ser escrito, um destino que não dá para ler até o fim: a resposta é DENY com um código de motivo, nunca ALLOW. **Por quê:** uma guarda que permite quando dá erro é uma guarda que o atacante desliga provocando erros. **Custo:** uma pane parece negação, então o portão registra em ERROR e expõe `counts()` para separar uma coisa da outra.

## 2. O ajuste seguro é o padrão

Todo padrão é o mais estrito: todo arg tem que vir do usuário, nenhum destino é permitido, coincidências são negadas, os digests usam chave aleatória, um portão sem registro de evidência gera aviso. Afrouxar é sempre explícito e visível na configuração. **Por quê:** as pessoas copiam o primeiro exemplo que funciona. **Custo:** a primeira integração é mais negada do que se espera, e por isso o README explica cada negação e como afrouxar de propósito.

## 3. Sem dependências em tempo de execução, sem modelo na decisão

O núcleo usa só a biblioteca padrão, e nenhuma decisão chama um modelo. **Por quê:** uma checagem de segurança deve ser determinística, auditável e barata o bastante para rodar em toda chamada, e cada dependência é mais uma coisa em que confiar. **Custo:** não há casamento aproximado, então paráfrase e tradução não são pegas pelo casamento (veja a decisão 5).

## 4. Dois modos com promessas diferentes

O modo A (plano selado) dá uma garantia estrutural: nada lido depois do selo muda quais ferramentas rodam nem seus args. O modo B (registro) funciona com um agente sem modificação e infere de onde veio cada valor. **Por quê:** o modo A é a resposta certa quando a tarefa pode ser planejada antes, e o modo B é o que a maioria dos agentes existentes consegue adotar hoje. **Custo:** duas coisas para documentar, e o README precisa deixar claro que o modo B é um filtro forte, não uma garantia.

## 5. Confiar só em tokens inteiros, e deixar o residual fazer o resto

No modo B, um valor consequente só é confiável se aparecer como tokens inteiros de um trecho confiável, com caixa, largura e espaços de agrupamento dobrados, e agrupamento só para valores na maior parte numéricos. O que não casar, enquanto houver conteúdo não confiável na janela, recebe a junção da janela, que é não confiável. **Por quê:** casamento por substring ou aproximado deixava "10000" virar confiável por causa de "100.00", e um pedaço de IBAN virar confiável sozinho. O residual conservador pega valores do atacante soletrados ou parafraseados sem precisar reconhecê-los. **Custo:** falsos positivos quando o modelo reformata ou calcula um valor (6 das 26 chamadas do banco benigno). Args tipados com limites resolvem os inofensivos.

## 6. Coincidência é um veredito próprio

Quando um valor confiável também aparece em conteúdo não confiável, o portão não finge saber qual dos dois o modelo usou. Nega por padrão, ou pergunta à pessoa com um token de uso único preso à chamada exata. **Por quê:** adivinhar para qualquer lado erra metade das vezes. **Custo:** o caminho de confirmação exige trabalho no app, então meça a taxa de coincidência antes de construí-lo.

## 7. Destinos lidos de todo arg e conferidos pelo nome

A checagem de saída olha todo arg, inclusive texto livre, e desembrulha redirecionadores. Hosts são comparados pelo nome, nunca resolvidos. O que não dá para ler até o fim (aninhado mais fundo que três níveis, mais de 64 destinos num arg) é negado. **Por quê:** a exfiltração costuma se esconder num corpo de texto ou num link, não num campo chamado `url`. Resolver nomes faria a decisão depender do DNS, que o atacante pode controlar. **Custo:** DNS rebinding e o que o cliente HTTP faz depois ficam fora do escopo, e listas longas de links são recusadas.

## 8. O registro prova decisões sem guardar os dados

Os registros guardam digests com chave dos valores, usuários e inquilinos pseudonimizados, destinos reduzidos a esquema e host, e texto livre passado pelo redator. Os registros são encadeados por hash, e checkpoints assinados com outra chave ficam guardados em outro lugar. **Por quê:** um registro de auditoria cheio de dado pessoal vira a próxima coisa a proteger. **Custo:** o registro continua sendo dado pessoal pseudonimizado (a chave liga de volta), e os registros depois do último checkpoint podem ser cortados do fim, então os checkpoints precisam rodar agendados.

## 9. Tokens de confirmação são de uso único e presos à chamada

Um token só funciona uma vez, e só para a mesma ferramenta, o mesmo chamador, o mesmo destino e uma impressão digital dos args. **Por quê:** senão um sim para uma chamada pode ser reaproveitado em outra. **Custo:** é preciso um armazenamento compartilhado quando vários workers atendem a mesma conversa (`PendingBackend`).

## 10. O benchmark é publicado com as falhas

Todo número sai de um comando que qualquer pessoa roda, as falhas conhecidas são listadas, e o banco do AgentDojo é apresentado como circular por construção. **Por quê:** uma afirmação de segurança que ninguém consegue conferir vale pouco. **Custo:** os números parecem menos impressionantes do que uma tabela escolhida a dedo.

## 11. O registro confere a janela em vez de confiar nela

O modo B depende de o registro saber o que está no contexto do modelo. O `observe()` compara os dois a cada turno: o texto que ninguém anotou entra como UNTRUSTED, e o `forget` é recusado enquanto o texto ainda está visível. **Por quê:** uma integração que esquecia uma fonte, ou tirava uma cedo demais, enfraquecia o modo B sem aviso. Agora o erro deixa tudo mais estrito. **Custo:** a integração precisa passar os textos da janela a cada turno e anotar o texto exatamente como o modelo recebe, incluindo o prompt de sistema.

## 12. Valores derivados só contam quando nomeiam a mesma coisa

Duas formas derivadas são confiáveis: o host de uma URL que o usuário escreveu, e um telefone com os mesmos dígitos com outra pontuação. Uma data calculada, uma soma ou uma tradução não, mesmo que isso deixe falsos positivos. **Por quê:** um host ou um número reespaçado apontam para o mesmo lugar que o usuário nomeou. Um valor calculado é justamente o que um atacante direcionaria. **Custo:** 6 das 26 chamadas do banco benigno continuam barradas.

## 13. Args afrouxados pulam o trabalho quando ele não muda o veredito

Um arg que aceita qualquer integridade, e para o qual até a junção da janela inteira pode ir ao chamador, recebe o rótulo da janela sem ser resolvido pedaço por pedaço. **Por quê:** corpos longos de texto livre eram a coisa mais lenta que o portão fazia, e a resposta já era conhecida. O rótulo da janela nunca é mais frouxo do que a resolução acharia, e um teste compara os dois caminhos. **Custo:** o registro de evidência mostra esse arg como CONSERVATIVE com o rótulo da janela, não com a cobertura dele.
