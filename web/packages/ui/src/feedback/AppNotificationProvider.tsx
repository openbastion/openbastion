import type { ReactNode } from "react";
import { Toaster, type ToasterProps } from "../components/Toaster";
import { ToastProvider } from "../hooks/use-toast";

export type AppNotificationProviderProps = {
  children: ReactNode;
  defaultDuration?: number;
  position?: ToasterProps["position"];
};

// The one place notifications are produced and shown: `useToast()` below, one live region here.
export function AppNotificationProvider({ children, defaultDuration, position }: AppNotificationProviderProps) {
  return (
    <ToastProvider defaultDuration={defaultDuration}>
      {children}
      <Toaster position={position} />
    </ToastProvider>
  );
}
