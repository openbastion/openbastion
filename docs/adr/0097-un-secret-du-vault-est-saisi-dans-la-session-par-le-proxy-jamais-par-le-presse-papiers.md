# ADR-0097 — Un secret du Vault est saisi dans la session par le proxy, et le copier-coller d'un mot de passe reste possible sans l'enregistrer

**Statut** `Proposé` · 13 novembre 2026 · étude demandée par le propriétaire du projet le 13 novembre 2026, à l'acceptation d'ADR-0096 : « Pour éviter que les mots de passe se retrouvent enregistrés en clair, est-ce que nous ne pourrions pas intégrer un mécanisme de saisie automatique comme op-forward, avec la possibilité de continuer à copier/coller les mots de passe ». `Accepté` seulement avec son go, cité avec sa date.

## Contexte

Avec ADR-0096, un texte collé dans une session RDP est enregistré avec la session. Un mot de passe collé l'est donc aussi.

**Ce que « en clair » veut dire ici.** L'enregistrement est chiffré au repos : une clé AES-256 par session, enveloppée par Transit (ADR-0070). Mais un auditeur autorisé qui rejoue la session lit le texte collé. Le mot de passe est donc lisible par toute personne qui a le droit de relire la session, longtemps après. C'est ce qu'il faut éviter.

**Ce qui existe déjà :**
- Le proxy ouvre la session avec le mot de passe de la cible, tiré du Vault : l'opérateur ne l'a jamais (invariant « secrets jamais dans le control plane », ADR-0039, ADR-0048).
- En SSH, l'enregistreur remplace une ligne tapée après une invite de mot de passe (`sudo`, `su`, `mysql`…) par `[redacted: input at a secret prompt]` (`pkg/proxycore/recording_tap.go`). C'est une heuristique sur l'invite, documentée comme telle.
- En RDP, les frappes ne sont pas enregistrées : seul l'écran l'est (ADR-0069 §6). Un mot de passe tapé dans un champ masqué n'y apparaît pas.

**Ce que fait op-forward** (github.com/eldorplus/op-forward) : la commande `op` de 1Password, lancée dans une VM, est relayée par un tunnel SSH jusqu'à l'hôte, qui l'exécute. Chaque opération sensible y demande une approbation biométrique (Touch ID). Le secret reste sur l'hôte jusqu'à ce qu'une personne approuve son usage, une fois. Les arguments sensibles sont masqués dans son journal.

**L'idée à transposer** : le secret part du coffre et va là où il sert, sans passer par une main ni par une trace lisible. Une approbation forte accompagne chaque usage, et seule la référence du secret est journalisée, jamais sa valeur.

## Options

**A. Saisir un secret du Vault (recommandée).** L'opérateur choisit, dans l'Admin UI, un secret qu'il a le droit d'utiliser. Il confirme par son second facteur (WebAuthn ou TOTP, ADR-0062, ADR-0065), l'équivalent du Touch ID d'op-forward. Le proxy demande alors le secret au Vault, par un scope à usage unique, et le saisit lui-même dans la session.
- **Ni le navigateur ni le presse-papiers** ne voient le secret.
- **L'enregistrement et l'audit gardent la référence** : « secret `<compte>` saisi à 14 h 32 ». Un auditeur sait donc exactement quoi a été saisi, sans lire la valeur. Lire la valeur passe par le Vault, qui a son propre audit.
- **« Enregistrer ou refuser » tient**, par référence : rien d'inconnu n'entre dans la session.

**B. Coller un mot de passe sans l'enregistrer.** Un bouton « Coller comme mot de passe », à côté du collage ordinaire d'ADR-0096. Le texte est livré à la cible. L'enregistrement et l'audit gardent sa taille et son empreinte SHA-256, pas son contenu.
- C'est le copier-coller que le propriétaire veut garder.
- Le prix : pour ce texte-là, l'auditeur ne sait plus ce qui est entré. Il peut seulement reconnaître une valeur s'il l'a déjà, en comparant l'empreinte.
- **Bornes**, pour qu'il reste un mot de passe et ne devienne pas un script soustrait à l'enregistrement : 128 caractères au plus, sur une seule ligne, sans tabulation. Un droit propre, refusé par défaut. Un événement d'audit à chaque usage.

**C. Une commande dans la cible, à la manière du shim d'op-forward.** Un outil installé sur la cible demanderait le secret au proxy par un canal de la session. Écartée :
- le secret atterrirait dans un processus et souvent dans la sortie de la cible, donc dans l'enregistrement SSH ;
- il faudrait installer et maintenir un logiciel sur chaque cible ;
- le modèle d'op-forward protège un développeur sur sa propre machine, pas un opérateur sur une cible privilégiée.

**D. Masquer après coup un mot de passe dans l'enregistrement**, en reconnaissant son allure. Écartée : une heuristique sur le contenu manque des secrets et en invente. L'heuristique SSH actuelle porte sur l'invite, pas sur le contenu, et elle reste.

## Décision proposée : A, et B en complément borné

1. **Droits**, refusés par défaut, à l'Authorization Service :
   - `secret:inject:<compte>` : saisir le secret de ce compte du Vault dans une session ;
   - `clipboard:secret-paste:<compte-cible>` : coller un mot de passe sans enregistrer son contenu, sur cette cible.
2. **Saisie d'un secret du Vault (A)** :
   - **Confirmation** : l'opérateur la donne par son second facteur, à chaque saisie, pas une fois par session. Sans second facteur enrôlé, la saisie est refusée.
   - **Scope** : le Broker émet un scope à usage unique pour ce compte et cette session. Le proxy l'échange au Vault comme pour l'ouverture de session, et efface le secret de sa mémoire après la saisie.
   - **En SSH**, le proxy écrit le secret sur l'entrée de la session, et l'enregistreur note la référence à la place de la ligne.
   - **En RDP**, deux voies, à départager par l'essai contre Windows :
     - (a) les frappes, comme l'opérateur les taperait (scancodes). Mais un caractère absent de la disposition de la cible ne passe pas (limite d'ADR-0088) ;
     - (b) le presse-papiers de la cible (ADR-0096) : le proxy y pose le secret, envoie Ctrl+V, puis vide le presse-papiers. Ce transfert-là est enregistré par référence, pas par contenu.
   - **Audit** : `session.secret_injected`, avec le compte du secret, la session et l'heure, jamais la valeur. Émis avant la saisie ; sans audit, pas de saisie.
3. **Coller comme mot de passe (B)** :
   - **Bornes** : 128 caractères, une seule ligne, sans tabulation.
   - **Ce qui reste** : l'enregistrement garde `[mot de passe collé : N caractères, empreinte …]`, et l'audit `session.clipboard.secret` avec la taille et l'empreinte.
   - **Sens unique** : de l'opérateur vers la cible seulement. Ce qui sort de la cible reste toujours enregistré en entier (ADR-0096) : c'est la voie d'une exfiltration.
4. **Admin UI** : un bouton « Saisir un secret » (liste des comptes permis, confirmation par le second facteur), et, à côté du collage d'ADR-0096, « Coller comme mot de passe ».
5. **Ce que cela ne protège pas, dit clairement** : si l'opérateur saisit un secret dans un champ **non masqué** (un éditeur de texte au lieu d'une invite de mot de passe), l'écran enregistré le montre. Le proxy ne voit pas le champ qui a le focus. L'Admin UI le rappelle à chaque saisie.

## Mise en œuvre envisagée

1. **SSH d'abord**, où la saisie est la plus simple et l'enregistreur prêt : droit, confirmation par second facteur, scope à usage unique, saisie, référence dans l'enregistrement, audit. Tests, et contre une vraie cible.
2. **RDP** : les deux voies (frappes, presse-papiers) éprouvées contre les cinq cibles Windows de la CI, puis une seule retenue.
3. **Coller comme mot de passe** : sur le canal d'ADR-0096 une fois livré, avec ses bornes.
4. **Admin UI**, et vérification dans le navigateur sans interface.

## Conséquences

- (+) Le mot de passe d'un compte du Vault n'est plus jamais lisible dans un rejeu : l'auditeur voit quel secret a servi et quand, pas sa valeur.
- (+) L'approbation forte à chaque usage, comme le Touch ID d'op-forward.
- (+) Le copier-coller d'un mot de passe reste possible, borné et audité.
- (−) B affaiblit « enregistrer ou refuser » pour le texte que l'opérateur déclare mot de passe. Les bornes empêchent d'y faire passer un script, mais pas un autre secret court. C'est le droit `clipboard:secret-paste` qui l'ouvre ou le ferme.
- (−) Un secret saisi dans un champ non masqué reste visible à l'écran enregistré.
- (−) En RDP, la saisie par frappes dépend de la disposition du clavier de la cible ; la voie du presse-papiers dépend d'ADR-0096.
- (−) Chaque saisie demande le second facteur : plus sûr, plus lent. Et c'est à construire : aujourd'hui, le second facteur n'est demandé qu'à la connexion (ADR-0062, ADR-0065), pas pour confirmer une action ; une confirmation par action, liée à la session et à usage unique, est un mécanisme nouveau.

## Alternatives envisagées

- **C, une commande sur la cible** : écartée (voir Options).
- **D, masquer après coup** : écartée (voir Options).
- **Ne rien faire et compter sur le chiffrement de l'enregistrement** : écartée. Le chiffrement protège le stockage, pas la relecture ; or le besoin est qu'un auditeur qui relit ne lise pas le secret.
