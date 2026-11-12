import type { SVGProps } from "react";

export interface IconProps extends Omit<SVGProps<SVGSVGElement>, "width" | "height"> {
  size?: number | string;
  ariaLabel?: string;
}

export function Encryption({ size = 24, ariaLabel, ...props }: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none" role="img" aria-hidden={ariaLabel ? undefined : true} aria-label={ariaLabel} stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      <style>{".accent{stroke:var(--ob-icon-accent, currentColor);} .secondary{stroke:var(--ob-icon-accent, currentColor);}"}</style>
      <path d="M12 2.8 20 6v5.6c0 5-3.4 8.1-8 9.9-4.6-1.8-8-4.9-8-9.9V6z"/><rect x="8.5" y="10" width="7" height="5.5" rx="1"/><path d="M10 10V8.5a2 2 0 0 1 4 0V10"/><path className="accent" d="M12 12v1.5"/>
      <path className="accent" d="M17 19h3"/>
    </svg>
  );
}
