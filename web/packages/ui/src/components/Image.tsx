import { forwardRef, useState, type ImgHTMLAttributes } from "react";
import { cn } from "../lib/cn";
import { resolveImageSource } from "../lib/image-helpers.js";

export type ImageProps = Omit<ImgHTMLAttributes<HTMLImageElement>, "src"> & { src?: string; fallback?: string; placeholder?: string };
export const Image = forwardRef<HTMLImageElement, ImageProps>(function Image({ src, fallback, placeholder = "Image indisponible", alt = "", className, onError, ...props }, ref) {
  const [failedSources, setFailedSources] = useState<string[]>([]);
  const safeSrc = [resolveImageSource(src), resolveImageSource(fallback)].find((candidate) => candidate && !failedSources.includes(candidate)) ?? null;
  if (!safeSrc) return <span className={cn("ob-image-placeholder", className)} role="img" aria-label={alt || placeholder}>{placeholder}</span>;
  return <img {...props} ref={ref} src={safeSrc} alt={alt} className={cn("ob-image", className)} onError={(event) => { setFailedSources((current) => current.includes(safeSrc) ? current : [...current, safeSrc]); onError?.(event); }} />;
});
Image.displayName = "Image";
