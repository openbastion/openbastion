---
name: frontend-testing-accessibility
description: Tests (Vitest, Testing Library) et accessibilité de l'Admin UI d'OpenBastion — à utiliser pour écrire ou corriger les tests d'un écran, ou vérifier qu'il reste utilisable au clavier et au lecteur d'écran.
---

# Tests et accessibilité frontend

## Tests

- `make ui-test` (Vitest, jsdom) ; `make ui-build` (vérification de types et construction).
- `fakeApi({"METHOD /chemin": {status, body}})` répond par route et enregistre les appels (`calls`) ; `fakeToken(username, roles)` fabrique un jeton lisible.
- Rendre un écran connecté : `SignedInContext.Provider value={{ api, who: null, signOut }}`.
- Par écran : le cas heureux, le refus (le texte de l'alerte contient le code et le motif), et ce qui ne doit **pas** partir (geste annulé, secret non réaffiché).
- `window.prompt` / `window.confirm` se remplacent dans le test et se restaurent dans un `finally`.
- Cherche par rôle et par étiquette (`getByRole`, `getByLabelText`) plutôt que par classe : c'est aussi un test d'accessibilité.

## Accessibilité

- Chaque champ a son `label` ; les messages ont leur rôle (`status`, `alert`) ; les boutons ont un texte qui dit l'action.
- Utilisable au clavier ; focus visible (`:focus` stylé dans `styles.css`).
- La compétence `better-accessibility` détaille le reste.
