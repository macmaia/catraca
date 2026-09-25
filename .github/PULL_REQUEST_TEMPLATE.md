<!-- Security fix? Please coordinate through SECURITY.md first. / Correção de segurança? Combine antes pelo SECURITY.md. -->

**What and why / O quê e por quê**

**Checklist**

- [ ] Tests added or updated, and `python -m unittest discover -s tests -t .` passes / Testes acrescentados ou atualizados, e a suíte passa
- [ ] If detection changed: `python -m bench.report --write` run and BENCHMARK.md updated in the same commit / Se a detecção mudou: `bench.report --write` rodado e BENCHMARK.md atualizado no mesmo commit
- [ ] Docs updated in both languages (EN-UK, then PT-BR) / Documentação atualizada nas duas línguas
- [ ] CHANGELOG.md entry / Entrada no CHANGELOG.md
- [ ] Defaults are still the safest option, any loosening is explicit / Os padrões continuam sendo a opção mais segura, e afrouxar é explícito
- [ ] No `Reason` code renamed or removed / Nenhum código de `Reason` renomeado ou removido
