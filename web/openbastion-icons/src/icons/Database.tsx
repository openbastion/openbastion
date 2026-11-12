import type { SVGProps } from "react";

export interface IconProps extends Omit<SVGProps<SVGSVGElement>, "width" | "height"> {
  size?: number | string;
  ariaLabel?: string;
}

export function Database({ size = 24, ariaLabel, ...props }: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none" role="img" aria-hidden={ariaLabel ? undefined : true} aria-label={ariaLabel} stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      <style>{".accent{stroke:var(--ob-icon-accent, currentColor);} .secondary{stroke:var(--ob-icon-accent, currentColor);}"}</style>
      <ellipse cx="12" cy="5.5" rx="8" ry="3"/><path d="M4 5.5v13c0 1.7 3.6 3 8 3s8-1.3 8-3v-13"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/><path className="accent" d="M8 18h8"/>
      <circle className="accent" cx="18.5" cy="5.5" r="1.2"/>
    </svg>
  );
}
