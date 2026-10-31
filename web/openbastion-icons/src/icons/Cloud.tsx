import type { SVGProps } from "react";

export interface IconProps extends Omit<SVGProps<SVGSVGElement>, "width" | "height"> {
  size?: number | string;
  ariaLabel?: string;
}

export function Cloud({ size = 24, ariaLabel, ...props }: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none" role="img" aria-hidden={ariaLabel ? undefined : true} aria-label={ariaLabel} stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
      <style>{".accent{stroke:var(--ob-icon-accent, #00D1FF);} .secondary{stroke:var(--ob-icon-accent, #00D1FF);}"}</style>
      <path d="M6.2 18.5h11.3a4.1 4.1 0 0 0 .3-8.2A5.8 5.8 0 0 0 6.7 9a4.8 4.8 0 0 0-.5 9.5z"/><path className="accent" d="M12 12v6m-2.2-2.2L12 18l2.2-2.2"/>
      <path className="accent" d="M17 19h3"/>
    </svg>
  );
}
