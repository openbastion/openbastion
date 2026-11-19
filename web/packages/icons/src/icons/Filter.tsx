import type { SVGProps } from "react";

export interface IconProps extends Omit<SVGProps<SVGSVGElement>, "width" | "height"> {
  size?: number | string;
  ariaLabel?: string;
}

export function Filter({ size = 24, ariaLabel, ...props }: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none" role="img" aria-hidden={ariaLabel ? undefined : true} aria-label={ariaLabel} stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <style>{`.accent{stroke:var(--ob-icon-accent, currentColor);} .secondary{stroke:var(--ob-icon-accent, currentColor);}`}</style>
      <path d="M4.5 7h15"/><path d="M7.5 12h9"/><path d="M10.5 17h3"/>
    </svg>
  );
}
