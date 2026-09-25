# Related work

*English (UK) first. [Versão em português mais abaixo](#trabalhos-relacionados-pt-br).*

catraca borrows its big ideas. This page says from where, and what's actually its own.

## Where the ideas come from

**CaMeL** (Debenedetti et al., "Defeating Prompt Injections by Design", arXiv:2503.18813v2, 2025). A privileged model writes the plan as code from the user's request only. A quarantined model reads untrusted data and can only return values. A custom interpreter tracks where every value came from and checks a policy before each tool call. In v2 of the paper it solves 77% of AgentDojo tasks with its security guarantee, against 84% undefended. **Mode A is a CaMeL-style plan, and a simpler one**: plans are straight-line (no loops or branches), there's no interpreter or capability system, and the plan is sealed with an HMAC and re-checked before every step. What it keeps is the core property: nothing read after the plan is sealed can change which tools run or where things go.

**FIDES** (Costa, Köpf et al., "Securing AI Agents with Information-Flow Control", arXiv:2505.23643, 2025). Information-flow control for agents: integrity and confidentiality labels travel with data through the planner, and policies are enforced deterministically. catraca's label model (an integrity lattice plus confidentiality scopes, joined when data mixes) is the same family of idea. The difference is **mode B infers labels by matching text** instead of tracking the flow, so it works with an unmodified agent and is weaker for it.

**The dual LLM pattern** (Simon Willison, 2023) and **design patterns for securing LLM agents** (Beurer-Kellner et al., arXiv:2506.08837, 2025). The separation between a model that plans and a model that only reads untrusted content, and the plan-then-execute pattern, are the conceptual base of mode A.

**Progent** (Shi, He, Wang, Li, Wu, Guo and Song, "Progent: Securing AI Agents with Privilege Control", arXiv:2504.11703, 2025). Programmable privilege control for tool calls: a policy language that decides which calls and args an agent may use. catraca's JSON policy plays the same role, with provenance as one of the conditions.

**Spotlighting** (Hines et al., arXiv:2403.14720, 2024). Marks untrusted text in the prompt so the model is less likely to follow it. It works inside the model and is probabilistic. catraca works outside the model, at the tool call, and is deterministic. The two combine well.

**Benchmarks and incidents.** AgentDojo (Debenedetti et al., NeurIPS 2024 Datasets and Benchmarks) and InjecAgent (arXiv:2403.02691) define the indirect-injection setting catraca targets, and several of our cases come from AgentDojo's injection goals. EchoLeak (arXiv:2509.10540, CVE-2025-32711) is the model for the exfiltration-through-a-link cases and for the egress checks.

## What's catraca's own

* **Token-level provenance for consequential args, with a conservative residual.** A value is trusted only if it appears as whole tokens of a trusted snippet. Anything that doesn't match, while untrusted content is in the window, is untrusted. That's what catches paraphrased or spelled-out attacker values without trying to detect them.
* **Coincidence as its own verdict.** When a trusted value also shows up in untrusted content, the gate can ask the person, with a single-use token bound to the exact call, instead of guessing.
* **Egress read out of every arg**, including free text, redirectors and parser tricks, checked against an allowlist and against provenance.
* **A decision log built for audit**: hash-chained, pseudonymised, replayable without the original data.
* **An honest benchmark**: detection and false positives on published case banks, known failures listed rather than hidden, and a one-command check anyone can run.

What catraca doesn't have yet is the number that would make it comparable with the systems above: attack success and utility on AgentDojo with a real model. Until that's published, please don't read the tables in [BENCHMARK.md](../BENCHMARK.md) as a comparison with CaMeL or FIDES.

---

<a id="trabalhos-relacionados-pt-br"></a>

# Trabalhos relacionados (pt-BR)

A catraca pega emprestadas as grandes ideias. Esta página diz de onde vieram, e o que é de fato dela.

## De onde vêm as ideias

**CaMeL** (Debenedetti et al., "Defeating Prompt Injections by Design", arXiv:2503.18813v2, 2025). Um modelo privilegiado escreve o plano em código só a partir do pedido do usuário. Um modelo em quarentena lê os dados não confiáveis e só pode devolver valores. Um interpretador próprio acompanha de onde veio cada valor e confere uma política antes de cada chamada de ferramenta. Na versão 2 do artigo, resolve no AgentDojo 77% das tarefas com a garantia de segurança, contra 84% sem defesa. **O modo A é um plano no estilo do CaMeL, e mais simples**: os planos são lineares (sem laços nem desvios), não há interpretador nem sistema de capacidades, e o plano é selado com HMAC e reconferido antes de cada passo. O que ele mantém é a propriedade central: nada lido depois do selo muda quais ferramentas rodam nem para onde as coisas vão.

**FIDES** (Costa, Köpf et al., "Securing AI Agents with Information-Flow Control", arXiv:2505.23643, 2025). Controle de fluxo de informação para agentes: rótulos de integridade e confidencialidade viajam com os dados pelo planejador, e as políticas são aplicadas de forma determinística. O modelo de rótulos da catraca (um reticulado de integridade mais escopos de confidencialidade, combinados quando os dados se misturam) é da mesma família. A diferença é que **o modo B infere os rótulos casando texto**, em vez de acompanhar o fluxo, então funciona com um agente sem modificação e é mais fraco por isso.

**O padrão dual LLM** (Simon Willison, 2023) e **os padrões de projeto para proteger agentes** (Beurer-Kellner et al., arXiv:2506.08837, 2025). A separação entre um modelo que planeja e um modelo que só lê conteúdo não confiável, e o padrão planejar-depois-executar, são a base conceitual do modo A.

**Progent** (Shi, He, Wang, Li, Wu, Guo e Song, "Progent: Securing AI Agents with Privilege Control", arXiv:2504.11703, 2025). Controle programável de privilégios para chamadas de ferramenta: uma linguagem de política que decide quais chamadas e args um agente pode usar. A política JSON da catraca faz o mesmo papel, com a proveniência como uma das condições.

**Spotlighting** (Hines et al., arXiv:2403.14720, 2024). Marca o texto não confiável no prompt para o modelo ter menos chance de segui-lo. Funciona dentro do modelo e é probabilístico. A catraca funciona fora do modelo, na chamada da ferramenta, e é determinística. Os dois se combinam bem.

**Benchmarks e incidentes.** O AgentDojo (Debenedetti et al., NeurIPS 2024 Datasets and Benchmarks) e o InjecAgent (arXiv:2403.02691) definem o cenário de injeção indireta que a catraca mira, e vários dos nossos casos vêm dos objetivos de injeção do AgentDojo. O EchoLeak (arXiv:2509.10540, CVE-2025-32711) é o modelo dos casos de exfiltração por link e das checagens de saída.

## O que é da catraca

* **Proveniência por token para args consequentes, com residual conservador.** Um valor só é confiável se aparecer como tokens inteiros de um trecho confiável. Qualquer coisa que não case, enquanto houver conteúdo não confiável na janela, é não confiável. É isso que pega valores do atacante parafraseados ou soletrados sem tentar detectá-los.
* **Coincidência como veredito próprio.** Quando um valor confiável também aparece em conteúdo não confiável, o portão pode perguntar à pessoa, com um token de uso único preso à chamada exata, em vez de adivinhar.
* **Saída extraída de todo arg**, incluindo texto livre, redirecionadores e truques de parser, conferida contra uma lista de permitidos e contra a proveniência.
* **Um registro de decisões feito para auditoria**: encadeado por hash, pseudonimizado, reproduzível sem o dado original.
* **Um benchmark honesto**: detecção e falso positivo em bancos de casos publicados, falhas conhecidas listadas em vez de escondidas, e uma conferência de um comando que qualquer pessoa roda.

O que a catraca ainda não tem é o número que a tornaria comparável aos sistemas acima: sucesso de ataque e utilidade no AgentDojo com um modelo de verdade. Até ele ser publicado, por favor não leia as tabelas do [BENCHMARK.md](../BENCHMARK.md) como uma comparação com o CaMeL ou o FIDES.
