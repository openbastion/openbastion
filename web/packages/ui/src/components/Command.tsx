import { createContext, forwardRef, useCallback, useContext, useEffect, useId, useMemo, useRef, useState, type ButtonHTMLAttributes, type HTMLAttributes, type InputHTMLAttributes, type ReactNode } from "react";
import { cn } from "../lib/cn";

type CommandContextValue = { query: string; setQuery: (value: string) => void; listId: string; listRef: React.RefObject<HTMLDivElement | null>; items: string[]; register: (value: string) => () => void; getItems: () => HTMLButtonElement[] };
const CommandContext = createContext<CommandContextValue | null>(null);
function useCommand() { const context = useContext(CommandContext); if (!context) throw new Error("Ce composant doit être utilisé dans Command."); return context; }
export type CommandProps = HTMLAttributes<HTMLDivElement> & { children: ReactNode };
export function Command({ children, className, ...props }: CommandProps) {
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<string[]>([]);
  const id = useId();
  const listId = `${id}-list`;
  const listRef = useRef<HTMLDivElement>(null);
  const register = useCallback((item: string) => {
    setItems((current) => current.includes(item) ? current : [...current, item]);
    return () => setItems((current) => current.filter((entry) => entry !== item));
  }, []);
  const value = useMemo<CommandContextValue>(() => ({ query, setQuery, listId, listRef, items, register, getItems: () => Array.from(listRef.current?.querySelectorAll<HTMLButtonElement>("[data-command-item]:not([hidden]):not(:disabled)") ?? []) }), [query, listId, items, register]);
  return <CommandContext.Provider value={value}><div {...props} className={cn("ob-command", className)}>{children}</div></CommandContext.Provider>;
}
export type CommandInputProps = Omit<InputHTMLAttributes<HTMLInputElement>, "type" | "value" | "onChange">;
export const CommandInput = forwardRef<HTMLInputElement, CommandInputProps>(function CommandInput({ className, onKeyDown, ...props }, ref) {
  const context = useCommand();
  return <input {...props} ref={ref} type="search" role="combobox" aria-autocomplete="list" aria-expanded="true" aria-controls={context.listId} value={context.query} onChange={(event) => context.setQuery(event.currentTarget.value)} onKeyDown={(event) => { onKeyDown?.(event); if (event.defaultPrevented) return; const items = context.getItems(); const current = items.indexOf(document.activeElement as HTMLButtonElement); if (event.key === "ArrowDown") { event.preventDefault(); items[Math.min(current + 1, items.length - 1)]?.focus(); } else if (event.key === "ArrowUp") { event.preventDefault(); items[Math.max(current < 0 ? items.length - 1 : current - 1, 0)]?.focus(); } else if (event.key === "Escape") { context.setQuery(""); (event.currentTarget as HTMLInputElement).blur(); } }} className={cn("ob-command-input", className)} />;
});
CommandInput.displayName = "CommandInput";
export type CommandListProps = HTMLAttributes<HTMLDivElement>;
export const CommandList = forwardRef<HTMLDivElement, CommandListProps>(function CommandList({ className, children, ...props }, ref) { const context = useCommand(); return <div {...props} ref={(node) => { context.listRef.current = node; if (typeof ref === "function") ref(node); else if (ref) ref.current = node; }} id={context.listId} role="listbox" className={cn("ob-command-list", className)}>{children}</div>; });
CommandList.displayName = "CommandList";
export type CommandItemProps = Omit<ButtonHTMLAttributes<HTMLButtonElement>, "value"> & { value: string; onSelect?: (value: string) => void };
export const CommandItem = forwardRef<HTMLButtonElement, CommandItemProps>(function CommandItem({ value, onSelect, className, children, ...props }, ref) { const context = useCommand(); useEffect(() => context.register(value), [context.register, value]); const visible = value.toLocaleLowerCase().includes(context.query.toLocaleLowerCase()); return <button {...props} ref={ref} type="button" role="option" aria-selected="false" data-command-item="" data-command-value={value} hidden={!visible} onClick={() => onSelect?.(value)} onKeyDown={(event) => { props.onKeyDown?.(event); if (event.defaultPrevented) return; const items = context.getItems(); const index = items.indexOf(event.currentTarget); if (event.key === "ArrowDown") { event.preventDefault(); items[Math.min(index + 1, items.length - 1)]?.focus(); } else if (event.key === "ArrowUp") { event.preventDefault(); items[Math.max(index - 1, 0)]?.focus(); } }} className={cn("ob-command-item", className)}>{children}</button>; });
CommandItem.displayName = "CommandItem";
export type CommandGroupProps = HTMLAttributes<HTMLDivElement>;
export const CommandGroup = forwardRef<HTMLDivElement, CommandGroupProps>(function CommandGroup({ className, ...props }, ref) { return <div {...props} ref={ref} role="group" className={cn("ob-command-group", className)} />; });
CommandGroup.displayName = "CommandGroup";
export function CommandEmpty({ children = "Aucun résultat." }: { children?: ReactNode }) { const context = useCommand(); return <div className="ob-command-empty" role="status" hidden={!context.query || context.items.some((item) => item.toLocaleLowerCase().includes(context.query.toLocaleLowerCase()))}>{children}</div>; }
export function CommandSeparator() { return <hr className="ob-command-separator" />; }
