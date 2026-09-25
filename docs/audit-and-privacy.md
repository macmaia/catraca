# Audit and privacy

*English (UK) first. [Versão em português mais abaixo](#auditoria-e-privacidade-pt-br).*

This page is for whoever has to answer "what does this log prove, and what personal data is in it". It isn't legal advice. Check the specifics with your DPO or counsel.

## What a record holds

For every decision: time, tool, verdict, reason, rule, latency, mode, and per arg its label, how it was resolved, where it came from and whether it was a coincidence. Values are a keyed digest and a length, never the value itself (unless you turn on `include_preview`). User and tenant ids are keyed digests, and so are `tenant:`/`user:` names inside labels. The destination keeps only scheme, host and port. Free text (`detail`, window values) goes through the redactor.

Egress target hosts are kept in clear, because "where did it try to send this" is the point of the record. An email target keeps its domain, with the full address as a digest.

## Pseudonymised, not anonymised

With the key, a digest can be linked back to a person: compute the digest of their id and look for it. So under LGPD and GDPR the log is still personal data (pseudonymised data, GDPR art. 4(5) and recital 26). Treat it that way: access control, retention, and a place in your records of processing.

## The key

The default key is random per process. That's the safest setting for privacy (nothing links records across restarts), but it makes the log much less useful for audit:

* the same person gets a different digest after every restart,
* a data subject request (LGPD art. 18, GDPR art. 15) can't be answered for older records,
* once the process is gone, nobody can check a digest against a value.

For audit, pass a stable `key=` from a secrets manager, never from the log or the repo. Rotating it starts new digests. Keep the old key, access-controlled, for as long as you keep the records it signed, or accept that those records can no longer be linked to anyone.

## Retention and erasure

The log has no retention of its own. Pick a period that fits your purpose (for AI systems under the EU AI Act, deployers of high-risk systems keep logs for at least six months, art. 26(6)), and delete whole files once they're past it. `RotatingJsonlSink` makes that easy.

Deleting single records breaks the hash chain on purpose. Two ways to handle a request to erase one person's data:

* **Drop the link, keep the record.** Records hold no direct identifiers, only digests. Destroying the key (for a time window, if you rotate) leaves records that can't be tied to anyone. That's usually the cleanest answer.
* **Rewrite and re-anchor.** Remove the records, rebuild the chain, take a new checkpoint, and keep a signed note of what was removed and why. Old checkpoints won't verify against the new file, so file the note with them.

## What the log is evidence of

* **That a decision was made, and why**, for every tool call that went through the gate: verdict, reason code, rule, and the provenance of each arg.
* **That the policy in hand gives the same answer** for the recomputed checks (integrity, confidentiality, egress). The caller check, and the destination when it was cut down, are read from the record, so they match by construction.
* **That the log wasn't edited in the middle**, via the hash chain, and wasn't rewritten before a checkpoint, via signed checkpoints kept elsewhere. Records after the latest checkpoint can be cut off the end without trace.

It is **not** evidence that:

* every tool call went through the gate (a call made around it leaves no record),
* the values were right or the user meant them (see "Choosing among trusted values" in the [threat model](threat-model.md)),
* no personal data is in it: the redactor misses names, addresses and free-form personal data.

## Where it may help with frameworks

Only as supporting evidence. None of these is met by a library alone.

| Framework | What the log can support |
|---|---|
| LGPD art. 46, GDPR art. 32 (security of processing) | a record of which automated actions were allowed or blocked, and why |
| LGPD art. 37, GDPR art. 30 (records of processing) | the tool calls an agent made on personal data, with pseudonymised subjects |
| EU AI Act art. 12 and art. 19 (logging for high-risk systems) | automatic, tamper-evident logs of the agent's actions |
| ISO/IEC 42001 (AI management system) | operational records and monitoring evidence for the AI system |

---

<a id="auditoria-e-privacidade-pt-br"></a>

# Auditoria e privacidade (pt-BR)

Esta página é para quem precisa responder "o que esse registro prova, e que dado pessoal tem nele". Não é aconselhamento jurídico. Confirme os detalhes com o seu encarregado (DPO) ou jurídico.

## O que um registro guarda

Para cada decisão: hora, ferramenta, veredito, motivo, regra, latência, modo e, por argumento, o rótulo, como foi resolvido, de onde veio e se foi coincidência. Valores viram um digest com chave e um tamanho, nunca o valor em si (a não ser que você ligue `include_preview`). Ids de usuário e de inquilino viram digest com chave, e o mesmo vale para nomes `tenant:`/`user:` dentro dos rótulos. O destino guarda só esquema, host e porta. Texto livre (`detail`, valores da janela) passa pelo redator.

Os hosts dos alvos de saída ficam em claro, porque "para onde tentou mandar" é justamente o que o registro precisa mostrar. Um alvo de email guarda o domínio, com o endereço completo como digest.

## Pseudonimizado, não anonimizado

Com a chave, um digest pode ser ligado de volta a uma pessoa: calcule o digest do id dela e procure. Então, pela LGPD e pelo GDPR, o registro continua sendo dado pessoal (dado pseudonimizado, GDPR art. 4(5) e considerando 26). Trate assim: controle de acesso, retenção, e um lugar no seu registro das operações de tratamento.

## A chave

A chave padrão é aleatória por processo. É o ajuste mais seguro para privacidade (nada liga registros entre reinícios), mas deixa o registro bem menos útil para auditoria:

* a mesma pessoa ganha um digest diferente a cada reinício,
* um pedido do titular (LGPD art. 18, GDPR art. 15) não pode ser atendido para registros antigos,
* quando o processo acaba, ninguém mais consegue conferir um digest contra um valor.

Para auditoria, passe uma `key=` estável vinda de um cofre de segredos, nunca do registro nem do repositório. Trocar a chave começa digests novos. Guarde a chave antiga, com acesso controlado, pelo tempo em que guardar os registros que ela assinou, ou aceite que esses registros não podem mais ser ligados a ninguém.

## Retenção e eliminação

O registro não tem retenção própria. Escolha um prazo que combine com a finalidade (para sistemas de IA sob o AI Act europeu, quem implanta sistema de alto risco guarda registros por pelo menos seis meses, art. 26(6)) e apague arquivos inteiros depois do prazo. O `RotatingJsonlSink` facilita isso.

Apagar registros avulsos quebra a cadeia de hash de propósito. Dois jeitos de atender um pedido de eliminação dos dados de uma pessoa:

* **Cortar o vínculo, manter o registro.** Os registros não têm identificador direto, só digests. Destruir a chave (de um período, se você faz rotação) deixa registros que não se ligam a ninguém. Em geral é a resposta mais limpa.
* **Reescrever e ancorar de novo.** Tirar os registros, refazer a cadeia, tirar um checkpoint novo, e guardar uma nota assinada do que saiu e por quê. Os checkpoints antigos não vão bater com o arquivo novo, então arquive a nota junto deles.

## Do que o registro é evidência

* **De que uma decisão foi tomada, e por quê**, para toda chamada de ferramenta que passou pelo portão: veredito, código de motivo, regra, e a proveniência de cada argumento.
* **De que a política em mãos dá a mesma resposta** nas checagens recalculadas (integridade, confidencialidade, saída). A checagem de quem chama, e o destino quando foi reduzido, são lidos do registro, então batem por construção.
* **De que o registro não foi editado no meio**, pela cadeia de hash, e não foi reescrito antes de um checkpoint, pelos checkpoints assinados guardados em outro lugar. Registros depois do último checkpoint podem ser cortados do fim sem deixar rastro.

**Não** é evidência de que:

* toda chamada de ferramenta passou pelo portão (uma chamada feita por fora não deixa registro),
* os valores estavam certos ou eram o que o usuário queria (veja "Escolha entre valores confiáveis" no [modelo de ameaças](threat-model.md)),
* não há dado pessoal nele: o redator não pega nomes, endereços nem dados pessoais em texto livre.

## Onde pode ajudar com normas

Só como evidência de apoio. Nenhuma delas é cumprida por uma biblioteca sozinha. A tabela acima vale para as duas línguas: LGPD art. 46 e GDPR art. 32 (segurança do tratamento), LGPD art. 37 e GDPR art. 30 (registro das operações), AI Act art. 12 e art. 19 (registros de sistemas de alto risco) e ISO/IEC 42001 (sistema de gestão de IA).
