# Secrets en mémoire et core dumps

## Processus concernés

`password-vault`, `ssh-proxy` et `rdp-vnc-proxy` appliquent le durcissement Linux au démarrage :

- `RLIMIT_CORE=0` (soft et hard) ;
- `PR_SET_DUMPABLE=0`, vérifié par `PR_GET_DUMPABLE` ;
- démarrage refusé si une opération ou sa vérification échoue.

Cette protection bloque les core dumps du processus et le ptrace ordinaire. Elle ne protège pas contre le noyau, l'hyperviseur ou un acteur disposant de capacités privilégiées adaptées.

## Durée de vie des buffers

Les credentials sont transportés en `[]byte`, transmis au protocole puis purgés par `Credential.Purge`. Les buffers JSON de transport et les buffers temporaires de rotation sont effacés au plus tôt. Les conversions en `string` sont évitées, sauf lorsque l'API publique d'une dépendance l'impose ; dans ce cas, leur portée doit être limitée au handshake.

`securemem.Zero` est une primitive best-effort. **Ce n'est pas** une mémoire sécurisée : Go peut créer des copies, le GC peut déplacer ou conserver des allocations, TLS et les bibliothèques ont leurs propres buffers, et le swap/la mémoire du noyau ne sont pas contrôlés par cette primitive. Aucun service ne doit promettre un effacement complet de la mémoire du processus.

## Exploitation et diagnostic

- Ne pas activer de collecteur de core dumps, de heap dump ou de profilage mémoire sur ces processus en production.
- Ne pas ajouter d'endpoint `pprof` à ces services.
- Ne jamais journaliser un credential, un corps de réponse Vault, un scope token ou un buffer d'authentification.
- Pour diagnostiquer un incident, utiliser les logs expurgés, métriques et traces sans payload ; le ptrace est volontairement restreint.
- Une modification de cette politique exige une ADR et une revue de menace.
