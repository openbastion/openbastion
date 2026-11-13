# ADR-0088 — RDP est ouvert aux opérateurs par la route écran de VNC, derrière un interrupteur éteint par défaut

**Statut** `Accepté` · 8 novembre 2026 · go du propriétaire du projet le 8 novembre 2026 : « Traite la réactivation et l'enregistrement contre Windows, puis la route opérateur et finir par le lecteur vidéo dans l'Admin UI ».

## Contexte

Le moteur RDP d'ADR-0071 ouvre une session complète contre FreeRDP 3 et contre Windows Server 2022 :
- CredSSP avec l'empreinte épinglée avant le secret ;
- image en 15, 16 et 32 bpp ;
- clavier et souris ;
- fragments Fast-Path et réactivation ;
- enregistrement rejouable à l'octet (incrément 73).

Pourtant, aucun opérateur ne peut l'atteindre. RDP est fermé à quatre endroits :
- le Session Broker refuse `connect` sur une session `rdp`, avant d'émettre un scope Vault (`ErrUnsupportedProtocol`, `409`) ;
- son routeur de proxys refuse `rdp` ;
- la route `establish-session` du proxy écran n'accepte que `vnc` ;
- la Gateway ne remet le chemin d'attache sécurisé (cookie `HttpOnly`) qu'à un ticket `vnc`.

L'Admin UI n'ouvre l'écran que d'une session VNC. Son clavier envoie des keysyms X11 : l'adaptateur RDP les refuse, il attend des scancodes.

ADR-0069 fixe les garanties d'un proxy RDP : NLA obligatoire, empreinte épinglée avant le secret, enregistrement obligatoire, canaux secondaires fermés, révocation effective. ADR-0071 réalise ces garanties dans `rdp-vnc-proxy`, et non dans un service `rdp-proxy` à part. Restent ouverts des critères de sortie de son incrément 2 :
- texte lisible par le cache de glyphes (les bitmaps suffisent à Windows et à FreeRDP, mesuré) ;
- claviers AZERTY et QWERTY vérifiés ;
- `session.recording_lost` sur une image de plus de 4 Mio.

## Décision

1. **Même route que VNC.** Une session `rdp` suit exactement le chemin d'une session `vnc` :
   - le Broker émet le scope Vault, puis demande l'établissement au pool des proxys écran ;
   - le proxy enregistre un ticket à usage unique de protocole RDP ;
   - la Gateway remet le chemin d'attache et son cookie `HttpOnly` ;
   - le WebSocket écran ouvre le codec RDP.

   Aucun contrat public ne change : `protocol` vaut déjà `rdp` dans `/api/v1`, le HELLO du flux écran porte déjà `ProtocolRDP`, et l'entrée porte déjà un `scancode`.
2. **Un interrupteur explicite, éteint par défaut, des deux côtés.**
   - Session Broker : `RDP_ENABLED`. Éteint, `connect` sur une session `rdp` reste refusé avant tout scope Vault (`409`), comme aujourd'hui.
   - `rdp-vnc-proxy` : `RDP_ENABLED`. Éteint, `establish-session` refuse `rdp` (`409`) et le codec RDP n'est pas construit.

   Seuls `true` et `false` sont lus ; toute autre valeur arrête le service au démarrage. Allumer l'un sans l'autre n'ouvre rien :
   - Broker éteint : `409 unsupported session protocol`, avant tout scope ;
   - proxy éteint : le proxy refuse le ticket, et le Broker répond `503`. Le scope Vault émis par un Broker allumé expire alors sans avoir été échangé.

   Les deux cas sont mesurés de bout en bout.
3. **Le codec dépend du ticket, pas de l'opérateur.** Le protocole vient de la session enregistrée (Broker), puis du ticket (proxy). Le WebSocket ne le choisit pas.
4. **Le clavier de l'Admin UI suit le protocole.** Pour une session RDP, le lecteur envoie le scancode Set 1 de la touche physique (`KeyboardEvent.code`, avec `0xE0` pour les touches étendues), sans keysym. Pour VNC, le keysym, sans scancode. Une touche hors table n'est pas envoyée. La disposition du clavier est celle de la cible (`keyboardLayout` 0) : l'opérateur tape sur les touches physiques, la cible les interprète.
5. **Ce qui ne s'ouvre pas.** L'interrupteur n'ouvre ni canal secondaire, ni authentification autre que le mot de passe Vault sous NLA, ni repli sans épinglage. Une session RDP break-glass reste soumise à « enregistrer ou refuser », comme VNC : le proxy refuse `break_glass`.

**Allumé par défaut le 13 novembre 2026.** Décision du propriétaire du projet, ce jour-là : « SCREEN_CLIPBOARD par défaut, RDP_ENABLED par défaut ». Elle a été prise une fois RDP prouvé contre cinq cibles Windows en CI (ADR-0071, « État au 13 novembre 2026 »).
- **Défaut** : `RDP_ENABLED` vaut `true` au Broker et au proxy écran quand il n'est pas fixé (code et compose). `RDP_ENABLED=false` à l'un des deux ferme RDP comme avant, et toute autre valeur arrête le service.
- **Ce qui ne change pas** : le Broker reste interne en refusant `rdp` quand on le construit sans `WithRDP`, et les garanties d'ADR-0069 tiennent (NLA, empreinte épinglée avant le secret, enregistrement obligatoire, canaux d'une liste fermée).
- **Pour une installation existante** : RDP s'ouvre à la mise à jour, si un compte `rdp` existe et qu'une politique `vault:account:*` le couvre. L'exploitant qui n'en veut pas met `RDP_ENABLED=false`.

## Conséquences

- (+) Un opérateur peut demander, faire approuver et ouvrir une session RDP depuis l'Admin UI, enregistrée et rejouable, avec les mêmes contrôles qu'une session VNC. Les preuves sont tirées de processus réels : parcours de bout en bout contre FreeRDP 3, depuis l'API publique.
- (+) Une installation qui n'allume rien garde exactement le comportement d'avant : RDP refusé avant tout scope.
- (−) Les critères de sortie d'ADR-0071 sont tenus depuis le 9 novembre 2026 : `recording_lost` au-delà de 4 Mio et QWERTY et AZERTY (incréments 76 et 77), texte lisible par bitmaps (ADR-0089). Allumer RDP reste le choix de l'exploitant. Allumer RDP est le choix de l'exploitant, en connaissance de ces limites (`docs/security/known-limitations.md`).
- (−) Un Broker allumé devant un proxy éteint émet un scope Vault inutile, borné par la durée de la session ; il n'est jamais échangé.
- (−) Le clavier passe par les touches physiques. Un caractère qu'aucune touche de la disposition de la cible ne donne ne s'envoie pas, et le presse-papiers est fermé.

## Alternatives envisagées

- **Ouvrir RDP sans interrupteur** : écartée. Les critères de sortie restants d'ADR-0071 ne sont pas tenus, et une installation existante changerait de surface sans le décider.
- **Un seul interrupteur, au Broker** : écartée. Le proxy accepterait tout `rdp` que lui demande un Broker, alors qu'il est la dernière défense avant la cible. Deux interrupteurs coûtent une variable de plus et ferment par défaut à chaque couche.
- **Un service `rdp-proxy` dédié, comme le prévoyait ADR-0069** : écartée par ADR-0071. Le relais écran, l'enregistrement et l'attache sont communs à RDP et VNC, et les dupliquer doublerait la surface.
- **Envoyer des keysyms à RDP et les traduire au proxy** : écartée. La traduction exigerait de connaître la disposition de la cible, que le proxy ignore. Le scancode de la touche physique est ce que RDP attend (`TS_KEYBOARD_EVENT`).
