import { createContext, useCallback, useContext, useId, useRef, useState, type ReactNode } from "react";

export type ToastVariant = "default" | "success" | "warning" | "danger";
export type ToastOptions = { title: string; description?: string; variant?: ToastVariant; duration?: number };
export type ToastEntry = ToastOptions & { id: string; duration: number; variant: ToastVariant };
type ToastContextValue = { toasts: ToastEntry[]; toast: (options: ToastOptions) => string; dismiss: (id: string) => void; defaultDuration: number };
const ToastContext = createContext<ToastContextValue | null>(null);

export type ToastProviderProps = { children: ReactNode; defaultDuration?: number };
export function ToastProvider({ children, defaultDuration = 5000 }: ToastProviderProps) {
  const [toasts, setToasts] = useState<ToastEntry[]>([]);
  const idPrefix = useId();
  const sequence = useRef(0);
  const toast = useCallback((options: ToastOptions) => {
    const id = `${idPrefix}-${++sequence.current}`;
    const entry: ToastEntry = { ...options, id, variant: options.variant ?? "default", duration: options.duration ?? defaultDuration };
    setToasts((current) => [...current, entry].slice(-5));
    return id;
  }, [defaultDuration, idPrefix]);
  const dismiss = useCallback((id: string) => setToasts((current) => current.filter((entry) => entry.id !== id)), []);
  return <ToastContext.Provider value={{ toasts, toast, dismiss, defaultDuration }}>{children}</ToastContext.Provider>;
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) throw new Error("useToast doit être utilisé dans ToastProvider ou Sonner.");
  return { toast: context.toast, dismiss: context.dismiss, toasts: context.toasts };
}
