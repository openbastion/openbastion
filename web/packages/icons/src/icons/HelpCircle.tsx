import type { SVGProps } from "react";

export interface IconProps extends Omit<SVGProps<SVGSVGElement>, "width" | "height"> {
  size?: number | string;
  ariaLabel?: string;
}

export function HelpCircle({ size = 24, ariaLabel, ...props }: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none" role="img" aria-hidden={ariaLabel ? undefined : true} aria-label={ariaLabel} stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <style>{`.accent{stroke:var(--ob-icon-accent, currentColor);} .secondary{stroke:var(--ob-icon-accent, currentColor);}`}</style>
      <circle cx="12" cy="12" r="8.5"/><path className="accent" d="M9.7 9.6a2.4 2.4 0 014.6.9c0 1.6-2.1 2.1-2.1 3.6"/><circle className="accent" cx="12" cy="17.1" r=".6" fill="currentColor" stroke="none"/>
    </svg>
  );
}
