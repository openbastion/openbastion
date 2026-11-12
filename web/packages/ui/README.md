# @openbastion/ui

Bibliothèque React/TypeScript partagée d’OpenBastion Infrastructure (ADR-0075). Elle fournit des composants accessibles, typés et sans logique métier, réutilisables par `admin-ui` et `user-portal`.

## Contrat

- React 19 et les primitives Radix utilisées sont des peer dependencies exactes fournies par l’application consommatrice ; cela évite une seconde instance de React et garde le contrôle des versions dans le lockfile de chaque application.
- Les composants simples utilisent les éléments HTML natifs et React. Radix UI est réservé aux interactions complexes (dialogues, menus, popovers et widgets composites) ; les composants OpenBastion encapsulent ces primitives sans exposer leurs API internes.
- Les styles sont pilotés par `@openbastion/design-tokens` et importés via `@openbastion/ui/styles.css`.
- Aucun composant n'appelle l'API, ne connaît les ressources PAM ou ne décide des autorisations.
- Les composants exposent des props TypeScript, conservent les attributs natifs et les refs lorsque pertinent, et ont des tests de contrat.

## Fondations disponibles

`Alert`, `Badge`, `Button`, `Card`, `Checkbox`, `Form`, `FormField`, `FormDescription`, `Input`, `InputOTP`, `Label`, `RadioGroup`, `RadioGroupItem`, `Select`, `Separator`, `Skeleton`, `Slider`, `Switch` et `Textarea`. Les overlays disponibles sont `Dialog`, `AlertDialog`, `DropdownMenu`, `Popover`, `Tooltip`, `Sheet` et `Drawer`, avec leurs sous-composants typés. Les primitives de navigation et de divulgation sont `Accordion`, `Collapsible`, `Breadcrumb`, `Command`, `ContextMenu`, `HoverCard`, `Menubar`, `NavigationMenu`, `Pagination`, `Sidebar` et `Tabs`. Le reste du catalogue est migré par lots ; sa présence dans la roadmap ne signifie pas qu'il est déjà exporté.

Importer `@openbastion/design-tokens/tokens.css` avant `@openbastion/ui/styles.css`, puis les styles applicatifs. Les applications consommatrices doivent déclarer les peer dependencies de Radix listées dans `package.json` et préserver une seule instance React dans leur bundler. Les anciennes façades `admin-ui/src/shared/ui/` restent temporairement disponibles pour préserver les imports existants.

## Catalogue cible

| État | Composants / utilitaires |
|---|---|
| Implémentés | Alert, Badge, Button, Card, Checkbox, Form, FormField, FormDescription, Input, InputOTP, Label, RadioGroup, RadioGroupItem, Select, Separator, Skeleton, Slider, Switch, Textarea, AlertDialog, Dialog, Drawer, DropdownMenu, Popover, Sheet, Tooltip |
| À réaliser — structure et navigation | Accordion, AspectRatio, Breadcrumb, Collapsible, Command, Menubar, NavigationMenu, Pagination, Resizable, ScrollArea, Sidebar, Tabs |
| À réaliser — actions et overlays | ContextMenu, HoverCard |
| À réaliser — formulaires | Calendar, Toggle, ToggleGroup |
| À réaliser — présentation | Avatar, Carousel, Chart, Image, Progress, Table |
| À réaliser — notifications et utilitaires | Sonner, Toast, Toaster, useToast, `image-helpers.js` |

`AspectRatio` figurait deux fois dans la demande initiale ; il n'est compté qu'une
fois. `image-helpers.js` et `useToast` sont des utilitaires/hooks, pas des
composants visuels autonomes. Chaque entrée est exportée seulement une fois son
implémentation, ses tests et ses contrats validés.
