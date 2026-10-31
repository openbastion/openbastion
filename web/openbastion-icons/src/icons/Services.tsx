import type { SVGProps } from "react";

export interface IconProps extends Omit<SVGProps<SVGSVGElement>, "width" | "height"> {
  size?: number | string;
  ariaLabel?: string;
}

export function Services({ size = 24, ariaLabel, ...props }: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none" role="img" aria-hidden={ariaLabel ? undefined : true} aria-label={ariaLabel} stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
      <style>{".accent{stroke:var(--ob-icon-accent, #00D1FF);} .secondary{stroke:var(--ob-icon-accent, #00D1FF);}"}</style>
      <path d="m10 2 4 0 .7 2.2 2 .9 2.1-1 2.1 3.6-1.7 1.6.1 2.2 1.6 1.6-2.1 3.6-2.1-.9-2 .9L14 19h-4l-.7-2.2-2-.9-2.1.9-2.1-3.6 1.7-1.6-.1-2.2L3 7.8l2.1-3.6 2.1 1 2-.9z"/><circle className="accent" cx="12" cy="10.5" r="3"/>
      <path className="accent" d="M18 3.5h2.5v2.5"/>
    </svg>
  );
}
