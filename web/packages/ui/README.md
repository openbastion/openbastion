# @openbastion/ui

Primitives CSS partagées de la charte OpenBastion Infrastructure (ADR-0075).

Le package fournit des classes visuelles génériques, sans logique métier, sans JavaScript navigateur et sans dépendance tierce :

- `.ob-button` et ses variantes `primary`, `secondary`, `danger`, `ghost` et `icon` ;
- `.ob-badge` et ses tons `neutral`, `info`, `success`, `warning` et `danger` ;
- `.ob-notice` et ses tons sémantiques ;
- `.ob-surface`, `.ob-page`, `.ob-page-header`, `.ob-hint`, `.ob-form-fields` et `.ob-form-actions`.

Importer `@openbastion/design-tokens/tokens.css` avant `@openbastion/ui/styles.css`, puis les styles applicatifs. Les applications restent propriétaires de leurs wrappers React, de leurs libellés, de leur état et de leurs règles métier.
