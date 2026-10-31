# Politique d'enregistrement

Chaque proxy lit `RECORDING_POLICY` :

| Valeur | Comportement |
|---|---|
| `required` (défaut) | Une session qui ne peut pas être enregistrée n'a pas lieu : refusée si le Command Recorder n'est pas prêt, terminée si une commande n'a pas pu y être enregistrée (la commande n'est alors **pas** exécutée sur la cible). |
| `best-effort` | La session continue si l'enregistrement échoue ; des commandes sont perdues. **Développement uniquement.** Le proxy le signale par un avertissement au démarrage. |

En mode `required`, `RECORDER_URL` (adresse du Command Recorder) est obligatoire : sans elle, le proxy refuse de démarrer. Une valeur de `RECORDING_POLICY` inconnue est une erreur fatale, pas un repli. Le recorder expose `GET /healthz` (le processus tourne) et `GET /readyz` (il pourrait écrire : base joignable et inscriptible) ; c'est `/readyz` que doivent sonder l'orchestrateur et la supervision, car un recorder dont la base est passée en lecture seule est « vivant » mais bloque en pratique tous les accès privilégiés.
