import type { SVGProps } from "react";

export interface IconProps extends Omit<SVGProps<SVGSVGElement>, "width" | "height"> {
  size?: number | string;
  ariaLabel?: string;
}

export function Notifications({ size = 24, ariaLabel, ...props }: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none" role="img" aria-hidden={ariaLabel ? undefined : true} aria-label={ariaLabel} stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
      <style>{".accent{stroke:var(--ob-icon-accent, #00D1FF);} .secondary{stroke:var(--ob-icon-accent, #00D1FF);}"}</style>
      <path d="M18 9a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4"/><path className="accent" d="M12 3V1.8"/>
      <path className="accent" d="M4 4h2.5M4 4v2.5"/>
    </svg>
  );
}
