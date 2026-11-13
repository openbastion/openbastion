import { forwardRef, type HTMLAttributes, type ReactNode } from "react";
import * as Primitive from "@radix-ui/react-accordion";
import { cn } from "../lib/cn";

export type AccordionSingleProps = { type: "single"; value?: string; defaultValue?: string; onValueChange?: (value: string) => void; collapsible?: boolean; disabled?: boolean; children: ReactNode; className?: string; orientation?: "horizontal" | "vertical"; dir?: "ltr" | "rtl" };
export type AccordionMultipleProps = { type: "multiple"; value?: string[]; defaultValue?: string[]; onValueChange?: (value: string[]) => void; disabled?: boolean; children: ReactNode; className?: string; orientation?: "horizontal" | "vertical"; dir?: "ltr" | "rtl" };
export function Accordion(props: AccordionSingleProps | AccordionMultipleProps) {
  if (props.type === "single") return <Primitive.Root type="single" value={props.value} defaultValue={props.defaultValue} onValueChange={props.onValueChange} collapsible={props.collapsible ?? true} disabled={props.disabled} orientation={props.orientation} dir={props.dir} className={cn("ob-accordion", props.className)}>{props.children}</Primitive.Root>;
  return <Primitive.Root type="multiple" value={props.value} defaultValue={props.defaultValue} onValueChange={props.onValueChange} disabled={props.disabled} orientation={props.orientation} dir={props.dir} className={cn("ob-accordion", props.className)}>{props.children}</Primitive.Root>;
}
export type AccordionItemProps = HTMLAttributes<HTMLDivElement> & { value: string; disabled?: boolean };
export const AccordionItem = forwardRef<HTMLDivElement, AccordionItemProps>(function AccordionItem({ className, ...props }, ref) { return <Primitive.Item {...props} ref={ref} className={cn("ob-accordion-item", className)} />; });
AccordionItem.displayName = "AccordionItem";
export type AccordionTriggerProps = HTMLAttributes<HTMLButtonElement>;
export const AccordionTrigger = forwardRef<HTMLButtonElement, AccordionTriggerProps>(function AccordionTrigger({ className, ...props }, ref) { return <Primitive.Header className="ob-accordion-header"><Primitive.Trigger {...props} ref={ref} className={cn("ob-accordion-trigger", className)} /></Primitive.Header>; });
AccordionTrigger.displayName = "AccordionTrigger";
export type AccordionContentProps = HTMLAttributes<HTMLDivElement>;
export const AccordionContent = forwardRef<HTMLDivElement, AccordionContentProps>(function AccordionContent({ className, ...props }, ref) { return <Primitive.Content {...props} ref={ref} className={cn("ob-accordion-content", className)} />; });
AccordionContent.displayName = "AccordionContent";
