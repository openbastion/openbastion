# Questions fréquentes

**Ma demande a été refusée, pourquoi ?**
Vous n'avez probablement pas de politique vous donnant droit à ce compte précis. Contactez votre administrateur — ce n'est pas quelque chose que vous pouvez contourner ou forcer depuis votre côté, par conception.

**Puis-je voir le mot de passe du compte cible ?**
Non, jamais, pour personne — pas même pour un administrateur. C'est le principe fondateur du système (Zero Standing Privilege), pas un bug ni une restriction qu'on pourrait lever sur demande.

**Ma session a expiré en plein milieu de mon travail, que faire ?**
Redemandez une session ([Demander une session](requesting-access.md)). C'est volontaire : une session à durée illimitée serait un accès permanent déguisé, exactement ce qu'OpenBastion existe pour éviter.

**La connexion est refusée avec « recording unavailable », que faire ?**
Le système d'enregistrement des sessions est momentanément indisponible, et OpenBastion refuse par principe une session qu'il ne pourrait pas enregistrer. Rien n'a été consommé : renouvelez votre demande dans quelques instants. Si c'est une urgence d'incident qui ne peut pas attendre, demandez à votre administrateur si un accès d'urgence (« break-glass ») est prévu pour votre rôle sur ce compte : il est désactivé par défaut, exige une justification précise, **l'accord d'une seconde personne** (vous ne pouvez pas approuver votre propre demande, et vous seul pouvez ensuite ouvrir la connexion), dure peu de temps — la durée compte à partir de l'accord —, et laisse une trace d'audit qui sera relue après coup. Sans réponse dans le délai (15 minutes par défaut), la demande expire : il faudra la refaire. Une session d'urgence est enregistrée au mieux, pas garantie.

**Je dois approuver une demande d'accès d'urgence : où la trouver ?**
Si l'administrateur a configuré un canal d'alerte, il vous a prévenu (le message nomme le compte, le demandeur et l'échéance, pas la justification). Dans tous les cas, la liste de ce que vous pouvez décider est `GET /sessions?status=pending_approval` : vous n'y voyez que les demandes que **vous** avez le droit d'approuver, jamais les vôtres, avec la justification. Une liste vide veut dire que rien ne vous attend — ou que vous n'avez pas ce droit ; si vous attendez une demande, vérifiez avec votre administrateur que votre rôle a l'autorité d'approuver ce compte. Une erreur 503 ne veut pas dire « rien à décider » : réessayez. Approuvez ou rejetez avec `POST /sessions/<id>/approve` ou `/reject`.

**Ma demande d'accès d'urgence est refusée avec « too many break-glass requests are waiting for a decision » (429) : pourquoi ?**
Vous avez déjà plusieurs demandes d'urgence en attente d'une décision — trois par défaut, votre administrateur peut avoir changé ce nombre (le message le dit). C'est une protection : personne ne peut noyer la liste de ses approbateurs, et le plafond est **le vôtre** — il n'empêche personne d'autre de demander. Une place se libère dès qu'une de vos demandes est approuvée, rejetée ou expirée (15 minutes par défaut) ; si l'une d'elles est devenue inutile, demandez à votre approbateur de la rejeter plutôt que d'attendre. La tentative refusée est tracée dans l'audit, comme toute demande.

**Ma connexion est refusée avec « too many login attempts » (429) : pourquoi ?**
La connexion est limitée pour freiner les essais de mots de passe : par défaut, cinq tentatives d'un coup depuis une même adresse, puis une par minute (votre administrateur peut avoir changé ces nombres). Attendez le nombre de secondes de l'en-tête `Retry-After` avant de réessayer, et pas moins : chaque tentative trop rapide ne fait que repousser le moment où une nouvelle sera acceptée. Si vous n'avez fait aucune tentative et que ce message revient, ou s'il touche tout le monde en même temps, prévenez votre administrateur : soit quelqu'un essaie des mots de passe depuis la même adresse que vous (un réseau d'entreprise partage une adresse), soit le Gateway ne distingue pas les utilisateurs derrière le reverse proxy et a besoin d'être réglé (`TRUSTED_PROXY_CIDRS`).

**Ma demande de session est refusée avec « too many session requests from this user … retry in N s » (429) : pourquoi ?**
Vous avez envoyé trop de demandes de session en peu de temps : par défaut, dix d'un coup, puis une toutes les dix secondes (votre administrateur peut avoir changé ces nombres — le message les donne). Chaque tentative compte, qu'elle ait été acceptée ou non. Attendez le nombre de secondes indiqué (en-tête `Retry-After`) et recommencez ; si un script ou un client boucle sur la demande, c'est lui qu'il faut corriger. Ce n'est **pas** le même message que « too many break-glass requests are waiting for a decision » : celui-là veut dire que vous avez trop de demandes d'urgence *en attente d'une décision*, et attendre quelques secondes n'y change rien. Une demande refusée pour cette raison n'est pas enregistrée comme une demande ; ce budget est **le vôtre** et ne retire rien aux autres. Si vous n'avez rien envoyé et que ce message revient, prévenez votre administrateur : quelqu'un d'autre utilise peut-être votre jeton.

**Approuver, rejeter, me connecter ou terminer une session est refusé avec « too many session actions from this user … retry in N s » (429) : pourquoi ?**
Vous avez envoyé trop d'actions de ce type en peu de temps : par défaut, dix d'un coup, puis une toutes les dix secondes (votre administrateur peut avoir changé ces nombres — le message les donne). Le compte est **un seul** pour approuver, rejeter, vous connecter et terminer, toutes sessions confondues : alterner entre les quatre ne redonne rien. Attendez le nombre de secondes indiqué (en-tête `Retry-After`) et recommencez ; si un script ou un client boucle, c'est lui qu'il faut corriger. Ce n'est **pas** le même compte que celui des demandes de session : avoir demandé beaucoup de sessions ne vous empêche pas de vous connecter à celle qu'on vous a accordée, et inversement. Lire une session ou lister les demandes en attente n'y compte pas. Une action refusée pour cette raison n'a rien fait. Si vous n'avez rien envoyé et que ce message revient, prévenez votre administrateur : quelqu'un d'autre utilise peut-être votre jeton — en pleine urgence, c'est ce qui vous empêcherait d'agir.

**Terminer une session est refusé (« refusé » / 403) : pourquoi ?**
Vous n'êtes ni le demandeur de cette session, ni titulaire du pouvoir de terminer les sessions de ce compte. Ce n'est pas lié à votre rôle d'administrateur éventuel : ce pouvoir se donne explicitement, compte par compte. Si une session doit vraiment être coupée, demandez à son demandeur, ou à une personne qui a ce pouvoir. « Déjà terminée » (409) veut dire que la session n'était plus active : rien à refaire. « 503 » veut dire que la session **n'a pas été terminée** (un service ne répondait pas, le SSH Proxy compris) : elle est toujours ouverte, renouvelez la commande.

**Ma connexion s'est coupée avec « session ended because it was terminated. » ?**
Quelqu'un — vous, le demandeur de la session, ou une personne habilitée — a mis fin à la session. Le message ne dit pas qui ; l'audit le sait. Redemandez une session si le travail n'est pas fini ([Demander une session](requesting-access.md)).

**Ma session s'est coupée à l'heure indiquée, même en pleine commande ?**
Oui : OpenBastion coupe toute session à son échéance, sans attendre. Redemandez-en une si le travail n'est pas fini ([Demander une session](requesting-access.md)).

**Est-ce que quelqu'un me surveille en temps réel ?**
Votre session est enregistrée pour être rejouable en cas de besoin (audit, incident), pas nécessairement regardée en direct. Les modalités précises de revue relèvent de la politique de votre organisation, pas d'OpenBastion lui-même.
