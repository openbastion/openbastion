import { forwardRef, type HTMLAttributes, type ReactNode } from "react";
import * as Primitive from "@radix-ui/react-tabs";
import { cn } from "../lib/cn";

export type TabsProps = { value?: string; defaultValue?: string; onValueChange?: (value: string) => void; orientation?: "horizontal" | "vertical"; dir?: "ltr" | "rtl"; activationMode?: "automatic" | "manual"; children: ReactNode; className?: string };
export function Tabs({ children, className, ...props }: TabsProps) { return <Primitive.Root {...props} className={cn("ob-tabs", className)}>{children}</Primitive.Root>; }
export type TabsListProps = HTMLAttributes<HTMLDivElement>;
export const TabsList = forwardRef<HTMLDivElement, TabsListProps>(function TabsList({ className, ...props }, ref) { return <Primitive.List {...props} ref={ref} className={cn("ob-tabs-list", className)} />; });
TabsList.displayName = "TabsList";
export type TabsTriggerProps = HTMLAttributes<HTMLButtonElement> & { value: string; disabled?: boolean };
export const TabsTrigger = forwardRef<HTMLButtonElement, TabsTriggerProps>(function TabsTrigger({ className, ...props }, ref) { return <Primitive.Trigger {...props} ref={ref} className={cn("ob-tabs-trigger", className)} />; });
TabsTrigger.displayName = "TabsTrigger";
export type TabsContentProps = HTMLAttributes<HTMLDivElement> & { value: string; forceMount?: true };
export const TabsContent = forwardRef<HTMLDivElement, TabsContentProps>(function TabsContent({ className, ...props }, ref) { return <Primitive.Content {...props} ref={ref} className={cn("ob-tabs-content", className)} />; });
TabsContent.displayName = "TabsContent";
