# ADR-0067 — Une session vers un compte qui l'exige attend l'approbation d'une autre personne, et porte un ticket au format déclaré

**Statut** `Proposé` · 1ᵉʳ novembre 2026 · lot de la v0.0.1, choisi par Bony Kiss le 1ᵉʳ novembre 2026 avec trois décisions qui sont les siennes : l'approbation est **un réglage du compte**, l'approbateur est **un approbateur déclaré** (quatre yeux), le ticket est **une référence au format déclaré** ; `Accepté` seulement avec son go sur ce texte

**Contexte** — Aujourd'hui une session ordinaire est accordée dès que la politique RBAC le permet (ADR-0001) : personne d'autre ne la voit avant qu'elle s'ouvre. Seul le break-glass attend une seconde personne (ADR-0011, ADR-0012, ADR-0013) — avec tout ce qu'il faut : une demande en attente, l'approbation par une autre personne que le demandeur, le droit d'approuver donné par une politique, la décision écrite à l'audit avant d'avoir effet, un compare-échange sur le statut, un plafond de demandes en attente par demandeur, la notification signée. La feuille de route v0.0.1 demande « une demande d'accès soumise à double validation avec ticket obligatoire » (`docs/roadmap.md` §3). Le Workflow Service et l'Approval Engine prévus par `system-overview.md` n'existent pas ; ce lot n'en crée pas : il étend le Broker, comme ADR-0011 l'a fait.

Invariants touchés : audit fail-closed ; l'identité qui décide est celle que la Gateway a vérifiée, jamais le corps de la requête ; quatre yeux.

**Décision**

1. **Le compte le dit** : un compte privilégié du Vault porte `approvalRequired` (faux par défaut). Il se pose à l'enregistrement (`POST /vault/accounts`), ou après par `PUT /vault/accounts/{id}/approval` `{"approvalRequired": true|false}` — même droit que la clé d'hôte (`vault:account-admin`), écrit à l'audit **avant** d'être fait (`vault.approval_set`, succès ou refus), comme ADR-0039. `GET /vault/accounts/{id}` le rend. Colonne `privileged_accounts.approval_required` (migration du Vault, idempotente).
2. **La demande** : `POST /sessions` prend `ticket`. Pour un compte qui exige l'approbation, le Broker (qui lit déjà le compte à la création, ADR-0043) exige un ticket qui suit `APPROVAL_TICKET_PATTERN` (une expression régulière RE2, ancrée de bout en bout ; par exemple `^(INC|CHG)[0-9]{7}$`). Sans la variable, le ticket est exigé quand même : 1 à 64 caractères, lettres, chiffres, `-`, `_`, `.`, `:`, `/`. Un ticket absent ou mal formé est un refus (`400`), écrit à l'audit comme toute demande refusée. OpenBastion ne vérifie pas que le ticket existe : il le montre à l'approbateur et l'écrit à l'audit.
3. **L'attente** : la session naît `pending_approval`, avec la même fenêtre de décision et le même plafond de demandes en attente par demandeur que le break-glass (`BREAKGLASS_APPROVAL_WINDOW_MINUTES`, `BREAKGLASS_MAX_PENDING_PER_REQUESTER`) ; l'événement `session.approval_requested` est écrit à l'audit **avant** d'être enregistré (sans audit, pas de demande) ; la notification signée d'ADR-0012 le dit, avec le ticket.
4. **L'approbation** : `POST /sessions/{id}/approve` et `/reject` (inchangés) décident aussi de ces demandes. L'approbateur doit **ne pas être le demandeur** (quatre yeux) et tenir une politique `session-approve:account:<id>` / `session:approve` ; la décision (`session.approval_approved` ou `session.approval_rejected`) est écrite à l'audit **avant** d'avoir effet ; un compare-échange sur `pending_approval` fait gagner la première décision. Approuvée, la session devient active pour la durée demandée, **à partir de l'approbation** ; sa connexion suit les règles ordinaires (l'enregistrement est exigé : aucune dérogation, contrairement au break-glass). Refusée ou non décidée à temps, elle ne s'ouvre jamais.
5. **Qui voit les demandes** : `GET /sessions?status=pending_approval` rend aussi ces demandes à qui peut les décider — et à personne d'autre, comme ADR-0012.
6. **Ce qui ne change pas** : un compte sans `approvalRequired` ouvre ses sessions comme aujourd'hui ; le break-glass garde ses règles (et son droit `breakglass-approve`) ; une demande déjà en attente n'est pas touchée si l'on change le réglage du compte (elle attend sa décision).
7. **L'Admin UI** : la case « Approbation requise » sur le compte ; le champ ticket à la demande de session quand le compte l'exige ; l'onglet des demandes en attente montre le ticket et laisse approuver ou refuser.

**Conséquences**

- (+) *À mesurer : rouge avant (une session vers un compte marqué s'ouvre sans approbation ; le réglage est ignoré), vert après sur processus réels — réglage posé, refusé sans droit, écrit à l'audit, refusé sans audit ; demande sans ticket, ticket mal formé, refusés ; demande en attente, invisible à qui ne peut pas décider ; le demandeur ne s'approuve pas ; un approbateur sans politique refusé ; approuvée, la session s'ouvre et s'enregistre ; refusée ou expirée, jamais ; deux décisions, une seule gagne ; tout à l'audit dans l'ordre ; ticket dans la notification —, mutations.*
- (−) **Un seul approbateur** : ni quorum (deux sur trois), ni N+1 hiérarchique (le manager de l'annuaire), ni chaîne d'étapes.
- (−) **Le ticket n'est pas vérifié** dans l'ITSM : un ticket inventé au bon format passe ; c'est à l'approbateur de le regarder.
- (−) La notification est le webhook signé d'ADR-0012 : pas de message Slack ou Teams mis en forme.
- (−) Les règles sont dans le Broker : un vrai moteur de workflow (étapes, délégations, horaires) reste à concevoir.

**Alternatives envisagées**

- **La politique d'accès décide** (« autorisé sous approbation ») : écartée par Bony Kiss ; plus fine, mais un changement du contrat de l'Authorization Service.
- **Le manager de l'annuaire approuve** : écartée par Bony Kiss ; seulement pour les comptes d'annuaire, et l'annuaire déciderait qui approuve.
- **Le ticket vérifié dans l'ITSM** : écartée par Bony Kiss ; une intégration par fournisseur, et un ITSM en panne bloquerait les accès.
- **Un nouveau service Workflow** : un service de plus pour une règle qui tient dans le Broker, qui a déjà la mécanique ; à rouvrir avec des étapes multiples.
