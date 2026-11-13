# @openbastion/icons

Official OpenBastion React icon library.

Source package in this monorepo: `web/packages/icons/` (ADR-0073). The npm package name and public exports remain `@openbastion/icons`.

Secure Access. Total Control.

## Installation

```bash
npm install @openbastion/icons
```

## Usage

```tsx
import {
  Shield,
  Lock,
  Server,
  Users,
  Database
} from "@openbastion/icons";

import "@openbastion/icons/styles.css";

export function SecurityDashboard() {
  return (
    <div>
      <Shield size={24} ariaLabel="Security" />
      <Lock size={20} ariaLabel="Locked" />
      <Server size={32} />
      <Users size={24} />
      <Database size={24} />
    </div>
  );
}
```

## Theming

```css
:root {
  --ob-icon-accent: #0B5ED7;
}

[data-theme="dark"] {
  --ob-icon-accent: #00D1FF;
}
```

Icons inherit their primary color from `currentColor`.

## Direct SVG access

SVG assets are available through:

```text
@openbastion/icons/assets/security/light/shield.svg
@openbastion/icons/assets/security/dark/shield.svg
```

## Development

```bash
cd web/packages/icons
npm ci
npm run audit:icons
npm run typecheck
npm run build
npm pack
```

## License

AGPL-3.0
