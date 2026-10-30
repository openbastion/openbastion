# Git

> Règle : applique-la à chaque ligne que tu écris. Si elle te paraît fausse pour un cas précis, ne l'enfreins pas en silence : suis-la, ou signale l'exception dans le rapport. Les interdictions absolues sont dans `policies/`.

1. Branche `main`. Un commit par incrément **cohérent et vérifié**, poussé aussitôt (`policies/release-management.md`). Ne mélange pas deux sujets.
2. Stage **explicitement** (`git add <fichiers>` ou `git add -A -- . ':!<exclusions>'`) ; lis `git status` avant ; n'embarque jamais ce que l'utilisateur a en cours sans qu'il l'ait demandé.
3. Message :

```
type(portée): sujet à l'indicatif, en français, sans point final

Corps : le pourquoi, ce qui change, ce qui est prouvé, ce qui reste (limites).
Une ligne par idée, pas de récit des essais.

<lignes d'attribution exigées par la session>
```

`type` ∈ `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `style` ; `portée` = composant(s) (`vault`, `ssh-proxy`, `agents`…).
4. Un commit oublié (un fichier non formaté) se corrige par un **nouveau** commit, jamais par `--amend` après push.
5. Pour mesurer un rouge sur l'ancien code : `git worktree add --detach <dir> <commit>`, puis `git worktree remove --force <dir>`.
