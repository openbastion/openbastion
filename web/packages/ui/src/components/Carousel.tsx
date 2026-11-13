import { useState, type HTMLAttributes, type ReactNode } from "react";
import { cn } from "../lib/cn";

export type CarouselProps = HTMLAttributes<HTMLDivElement> & { items: ReactNode[]; label: string; index?: number; defaultIndex?: number; onIndexChange?: (index: number) => void; loop?: boolean };
export function Carousel({ items, label, index, defaultIndex = 0, onIndexChange, loop = false, className, ...props }: CarouselProps) {
  const [internalIndex, setInternalIndex] = useState(defaultIndex);
  const active = Math.min(Math.max(index ?? internalIndex, 0), Math.max(items.length - 1, 0));
  const setActive = (next: number) => { if (!items.length) return; const bounded = loop ? (next + items.length) % items.length : Math.min(Math.max(next, 0), items.length - 1); if (index === undefined) setInternalIndex(bounded); onIndexChange?.(bounded); };
  return <section {...props} aria-label={label} aria-roledescription="carrousel" className={cn("ob-carousel", className)}><div className="ob-carousel-viewport"><div className="ob-carousel-slide" role="group" aria-roledescription="diapositive" aria-label={`${active + 1} sur ${items.length}`}>{items[active]}</div></div><div className="ob-carousel-controls"><button type="button" className="ob-carousel-control" aria-label="Élément précédent" disabled={!loop && active === 0} onClick={() => setActive(active - 1)}>Précédent</button><span aria-live="polite" aria-atomic="true">{items.length ? `${active + 1} / ${items.length}` : "0 / 0"}</span><button type="button" className="ob-carousel-control" aria-label="Élément suivant" disabled={!loop && active >= items.length - 1} onClick={() => setActive(active + 1)}>Suivant</button></div></section>;
}
