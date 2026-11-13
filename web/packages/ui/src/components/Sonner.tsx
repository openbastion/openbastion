import type { ReactNode } from "react";
import { ToastProvider } from "../hooks/use-toast";
import { Toaster } from "./Toaster";

export type SonnerProps = { children: ReactNode; position?: "top-left" | "top-right" | "bottom-left" | "bottom-right" | "top-center" | "bottom-center"; duration?: number };
export function Sonner({ children, position = "bottom-right", duration = 5000 }: SonnerProps) {
  return <ToastProvider defaultDuration={duration}>{children}<Toaster position={position} /></ToastProvider>;
}
