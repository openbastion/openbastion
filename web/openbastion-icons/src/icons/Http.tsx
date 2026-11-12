import type { SVGProps } from "react";

export interface IconProps extends Omit<SVGProps<SVGSVGElement>, "width" | "height"> {
  size?: number | string;
  ariaLabel?: string;
}

export function Http({ size = 24, ariaLabel, ...props }: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none" role="img" aria-hidden={ariaLabel ? undefined : true} aria-label={ariaLabel} stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      <style>{".accent{stroke:var(--ob-icon-accent, currentColor);} .secondary{stroke:var(--ob-icon-accent, currentColor);}"}</style>
      <circle cx="12" cy="12" r="9"/><path d="M3.5 12h17M12 3c2.5 2.5 3.5 5.5 3.5 9S14.5 18.5 12 21c-2.5-2.5-3.5-5.5-3.5-9S9.5 5.5 12 3z"/><path className="accent" d="M5.5 7h13M5.5 17h13"/>
      <path className="accent" d="M18 3.5h2.5v2.5"/>
    </svg>
  );
}
