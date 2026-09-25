# Security policy

*English (UK) first, pt-BR below.*

## Reporting a vulnerability

Please don't open a public issue. Use GitHub's private reporting instead: the **Security** tab of this repository, then **Report a vulnerability**. Only the maintainers see it.

Useful things to include: the version or commit, a minimal config (channels, policy, egress) and the call that got through, and what you expected the gate to say. A failing test case is the best report there is.

What happens next:

* We'll acknowledge it within 5 working days.
* We'll tell you whether we see it as a vulnerability within 14 days, and roughly when a fix will land.
* We'll agree a disclosure date with you. The default is 90 days after the report or when the fix ships, whichever comes first.
* You'll be credited in the advisory and the changelog, unless you'd rather not be.

## Safe harbour

If you research catraca in good faith and follow this policy, we won't pursue or support legal action against you for that research, and we'll treat it as authorised. Good faith means you test against your own installation or with the owner's permission, avoid harming others or accessing their data beyond what the finding needs, give us a reasonable chance to fix things before going public, and don't ask for payment in exchange for not disclosing. If in doubt about something, ask first through the private channel above.

## What counts

Anything that makes the gate return ALLOW when its documented behaviour says it shouldn't. For example:

* a value from an UNTRUSTED channel reaching a consequential arg without DENY or REQUIRE_CONFIRMATION, through a variant `normalise.py` claims to handle.
* an egress target that slips past extraction or the allowlist.
* a confirmation token that works for a different call.
* a sealed plan that runs after being changed.
* a way to break or rewrite the evidence chain without `verify` noticing.
* any exception path that ends in ALLOW.
* a default that's looser than the docs say.

## What doesn't

These are documented limits, not vulnerabilities (see [docs/threat-model.md](docs/threat-model.md)):

* paraphrase or translation getting past mode B.
* anything that needs control of the policy, config, keys or host.
* DNS rebinding after a host is allowed by name.
* data leaking in the model's reply text rather than a tool call.

New cases of the first kind are still very welcome as a normal issue or pull request against `bench/propagation_cases.json`. They make the published numbers more honest.

## Supported versions

Before 1.0, only the latest release gets fixes.

---

# Política de segurança (pt-BR)

## Como relatar uma vulnerabilidade

Por favor, não abra issue pública. Use o relato privado do GitHub: aba **Security** deste repositório, depois **Report a vulnerability**. Só os mantenedores veem.

Ajuda incluir: a versão ou o commit, uma configuração mínima (canais, política, saída) e a chamada que passou, e o que você esperava que o portão respondesse. Um caso de teste que falha é o melhor relato possível.

O que acontece depois:

* Confirmamos o recebimento em até 5 dias úteis.
* Dizemos se consideramos vulnerabilidade em até 14 dias, e mais ou menos quando sai a correção.
* Combinamos a data de divulgação com você. O padrão é 90 dias depois do relato ou quando a correção sair, o que vier primeiro.
* Você recebe crédito no aviso e no changelog, a não ser que prefira não receber.

## Porto seguro

Se você pesquisar a catraca de boa-fé e seguir esta política, não vamos mover nem apoiar ação judicial contra você por essa pesquisa, e vamos tratá-la como autorizada. Boa-fé quer dizer testar na sua própria instalação ou com permissão do dono, evitar prejudicar terceiros ou acessar dados deles além do que a descoberta exige, dar uma chance razoável de corrigirmos antes de tornar público, e não pedir pagamento em troca de não divulgar. Na dúvida, pergunte antes pelo canal privado acima.

## O que conta

Qualquer coisa que faça o portão devolver ALLOW quando o comportamento documentado diz que não devia. Por exemplo:

* um valor de canal UNTRUSTED chegando a um arg consequente sem DENY ou REQUIRE_CONFIRMATION, por uma variante que o `normalise.py` diz tratar.
* um alvo de saída que escapa da extração ou da lista de permitidos.
* um token de confirmação que funciona para outra chamada.
* um plano selado que roda depois de alterado.
* um jeito de quebrar ou reescrever a cadeia de evidência sem o `verify` perceber.
* qualquer caminho de exceção que termine em ALLOW.
* um padrão mais frouxo do que a documentação diz.

## O que não conta

São limites documentados, não vulnerabilidades (veja [docs/threat-model.md](docs/threat-model.md)):

* paráfrase ou tradução passando pelo modo B.
* qualquer coisa que exija controle da política, da configuração, das chaves ou do host.
* DNS rebinding depois que um host é permitido pelo nome.
* dado vazando no texto da resposta do modelo e não numa chamada de ferramenta.

Casos novos do primeiro tipo são muito bem-vindos como issue ou pull request normal contra `bench/propagation_cases.json`. Eles deixam os números publicados mais honestos.

## Versões com suporte

Antes da 1.0, só a última versão recebe correções.
