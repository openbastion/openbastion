import type { SVGProps } from "react";

export interface IconProps extends Omit<SVGProps<SVGSVGElement>, "width" | "height"> {
  size?: number | string;
  ariaLabel?: string;
}

export function SessionSecurity({ size = 24, ariaLabel, ...props }: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none" role="img" aria-hidden={ariaLabel ? undefined : true} aria-label={ariaLabel} stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
      <style>{".accent{stroke:var(--ob-icon-accent, #00D1FF);} .secondary{stroke:var(--ob-icon-accent, #00D1FF);}"}</style>
      <rect x="2.8" y="3.5" width="18.4" height="13" rx="1.8"/><path d="M8 21h8m-4-4.5V21"/><path className="accent" d="m7 12 3-3 2 2 4-4"/>
      <circle className="accent" cx="18.5" cy="5.5" r="1.2"/>
    </svg>
  );
}
