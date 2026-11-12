import type { SVGProps } from "react";

export interface IconProps extends Omit<SVGProps<SVGSVGElement>, "width" | "height"> {
  size?: number | string;
  ariaLabel?: string;
}

export function Proxy({ size = 24, ariaLabel, ...props }: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none" role="img" aria-hidden={ariaLabel ? undefined : true} aria-label={ariaLabel} stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      <style>{".accent{stroke:var(--ob-icon-accent, currentColor);} .secondary{stroke:var(--ob-icon-accent, currentColor);}"}</style>
      <path d="M9.5 14.5 7.8 16.2a4 4 0 0 1-5.7-5.7l4-4a4 4 0 0 1 5.7 0"/><path d="m14.5 9.5 1.7-1.7a4 4 0 0 1 5.7 5.7l-4 4a4 4 0 0 1-5.7 0"/><path className="accent" d="m8.5 15.5 7-7"/>
      <path className="accent" d="M4 4h2.5M4 4v2.5"/>
    </svg>
  );
}
