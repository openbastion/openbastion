import { forwardRef, useState, type HTMLAttributes, type ReactNode } from "react";
import { cn } from "../lib/cn";
import { isSafeImageSource } from "../lib/image-helpers.js";

export type AvatarProps = HTMLAttributes<HTMLSpanElement> & { src?: string; alt?: string; fallback: ReactNode; size?: "sm" | "md" | "lg" };
export const Avatar = forwardRef<HTMLSpanElement, AvatarProps>(function Avatar({ src, alt = "", fallback, size = "md", className, ...props }, ref) {
  const [failed, setFailed] = useState(false);
  const showImage = Boolean(src && isSafeImageSource(src) && !failed);
  return <span {...props} ref={ref} className={cn("ob-avatar", `ob-avatar--${size}`, className)}>{showImage ? <img src={src} alt={alt} onError={() => setFailed(true)} /> : <span aria-label={alt || undefined}>{fallback}</span>}</span>;
});
Avatar.displayName = "Avatar";
