---
name: web-application-security
description: Sécurité navigateur et API publique d'OpenBastion (CSP, origine unique, jeton, XSS, en-têtes de la Gateway) — à utiliser pour toute modification de l'Admin UI, de la façon dont la Gateway la sert, ou d'une route publique.
---

# Sécurité des applications web

## Ce qui tient aujourd'hui (ADR-0036, ADR-0035)

- La Gateway sert l'UI sous `/ui/` avec une CSP sans script en ligne ni origine tierce, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer` ; même origine que l'API : aucune règle CORS ouverte.
- Le jeton est en mémoire seulement ; la connexion OIDC est un code d'autorisation avec PKCE (S256), `state` et `nonce` à usage unique.
- `/auth/login` est limité par adresse (ADR-0015) ; `POST /sessions` et les actions par utilisateur vérifié (ADR-0014, ADR-0016).

## Vérifie à chaque changement

1. Tout contenu venu de l'API est rendu en texte (un enregistrement contient ce qu'un opérateur a tapé : test existant avec `<img onerror>`).
2. Aucun secret dans une URL, un journal du navigateur, un stockage persistant.
3. La Gateway ne prend du client que ce qui lui revient ; l'identité vient du jeton (test d'attaque : un corps qui revendique `actorId` ou `actorRoles` est ignoré).
4. Les en-têtes de sécurité restent sur chaque réponse de `/ui/` (tests de la Gateway).
5. Un changement de la configuration Vite n'a lieu que sous `BASE44_PREVIEW_MODE=1`.
