import type { HTMLAttributes, ReactNode } from "react";
import { cn } from "../lib/cn";

export type AspectRatioValue = "square" | "video" | "photo" | "portrait";
export type AspectRatioProps = HTMLAttributes<HTMLDivElement> & { ratio?: AspectRatioValue; children: ReactNode };
export function AspectRatio({ ratio = "video", className, ...props }: AspectRatioProps) { return <div {...props} data-ratio={ratio} className={cn("ob-aspect-ratio", className)} />; }
