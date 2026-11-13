# @openbastion/ui

Bibliothèque React/TypeScript partagée d’OpenBastion Infrastructure (ADR-0075). Elle fournit des composants accessibles, typés et sans logique métier, réutilisables par `admin-ui` et `user-portal`.

## Contrat

- React 19 et les primitives Radix utilisées sont des peer dependencies exactes fournies par l’application consommatrice ; cela évite une seconde instance de React et garde le contrôle des versions dans le lockfile de chaque application.
- Les composants simples utilisent les éléments HTML natifs et React. Radix UI est réservé aux interactions complexes (dialogues, menus, popovers et widgets composites) ; les composants OpenBastion encapsulent ces primitives sans exposer leurs API internes.
- Les styles sont pilotés par `@openbastion/design-tokens` et importés via `@openbastion/ui/styles.css`.
- Aucun composant n'appelle l'API, ne connaît les ressources PAM ou ne décide des autorisations.
- Les composants exposent des props TypeScript, conservent les attributs natifs et les refs lorsque pertinent, et ont des tests de contrat.

## Fondations disponibles

`Alert`, `Badge`, `Button`, `Card`, `Checkbox`, `Form`, `FormField`, `FormDescription`, `Input`, `InputOTP`, `Label`, `RadioGroup`, `RadioGroupItem`, `Select`, `Separator`, `Skeleton`, `Slider`, `Switch`, `Table`, `Textarea` et tous les composants du catalogue listés ci-dessous. Les overlays disponibles sont `Dialog`, `AlertDialog`, `DropdownMenu`, `Popover`, `Tooltip`, `Sheet` et `Drawer`, avec leurs sous-composants typés. Les primitives de navigation et de divulgation sont `Accordion`, `Collapsible`, `Breadcrumb`, `Command`, `ContextMenu`, `HoverCard`, `Menubar`, `NavigationMenu`, `Pagination`, `Sidebar` et `Tabs`. Les composants avancés incluent `AspectRatio`, `Avatar`, `Calendar`, `Carousel`, `Chart`, `Image`, `Progress`, `Resizable`, `ScrollArea`, `Toggle` et `ToggleGroup` ; les fonctions `isSafeImageSource` et `resolveImageSource` centralisent la validation des sources d'image. Le système de notifications comprend `Sonner`, `ToastProvider`, `Toast`, `Toaster` et `useToast` ; la file visible est limitée à cinq notifications. Tous les composants demandés sont maintenant exportés depuis l'entrée publique `@openbastion/ui` ; leurs API et leurs tests sont suivis par ADR-0073.

Importer `@openbastion/design-tokens/tokens.css` avant `@openbastion/ui/styles.css`, puis les styles applicatifs. Les applications consommatrices doivent déclarer les peer dependencies de Radix listées dans `package.json` et préserver une seule instance React dans leur bundler. Les anciennes façades `admin-ui/src/shared/ui/` restent temporairement disponibles pour préserver les imports existants.

## Catalogue livré

| Domaine | Composants / utilitaires |
|---|---|
| Structure | Accordion, AspectRatio, Avatar, Card, Collapsible, Resizable, ScrollArea, Separator, Skeleton |
| Navigation | Breadcrumb, Command, Menubar, NavigationMenu, Pagination, Sidebar, Tabs |
| Actions et overlays | AlertDialog, Alert, Button, ContextMenu, Dialog, Drawer, DropdownMenu, HoverCard, Popover, Sheet, Tooltip |
| Formulaires | Checkbox, Form, Input, InputOTP, Label, RadioGroup, Select, Slider, Switch, Table, Textarea, Toggle, ToggleGroup |
| Présentation | Badge, Calendar, Carousel, Chart, Image, Progress |
| Notifications | Sonner, Toast, ToastProvider, Toaster, useToast |
| Utilitaires | `image-helpers.js`, `isSafeImageSource`, `resolveImageSource` |

`AspectRatio` n'est compté qu'une fois (il figurait deux fois dans la demande). `image-helpers.js` et `useToast` sont des utilitaires/hooks et non des composants visuels autonomes.
