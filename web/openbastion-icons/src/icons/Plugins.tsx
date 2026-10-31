import type { SVGProps } from "react";

export interface IconProps extends Omit<SVGProps<SVGSVGElement>, "width" | "height"> {
  size?: number | string;
  ariaLabel?: string;
}

export function Plugins({ size = 24, ariaLabel, ...props }: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none" role="img" aria-hidden={ariaLabel ? undefined : true} aria-label={ariaLabel} stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
      <style>{".accent{stroke:var(--ob-icon-accent, #00D1FF);} .secondary{stroke:var(--ob-icon-accent, #00D1FF);}"}</style>
      <path d="m12 2.8 9 4.7v9L12 21.2 3 16.5v-9z"/><path d="m3.3 7.5 8.7 4.7 8.7-4.7M12 12.2v9"/><path className="accent" d="m8 5 9 4.8"/>
      <path className="accent" d="M4 4h2.5M4 4v2.5"/>
    </svg>
  );
}
