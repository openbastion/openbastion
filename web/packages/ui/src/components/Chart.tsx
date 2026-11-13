import type { HTMLAttributes } from "react";
import { cn } from "../lib/cn";

export type ChartDatum = { label: string; value: number };
export type ChartProps = HTMLAttributes<HTMLElement> & { title: string; description?: string; data: ChartDatum[]; type?: "bar" | "line"; valueLabel?: string };
export function Chart({ title, description, data, type = "bar", valueLabel = "Valeur", className, ...props }: ChartProps) {
  const max = Math.max(1, ...data.map((point) => Number.isFinite(point.value) ? Math.max(point.value, 0) : 0));
  const values = data.map((point, index) => ({ ...point, x: data.length < 2 ? 160 : 18 + index * (284 / (data.length - 1)), y: 132 - (Math.max(0, Number.isFinite(point.value) ? point.value : 0) / max) * 112 }));
  const summary = data.map((point) => `${point.label}: ${point.value}`).join(", ");
  return <figure {...props} className={cn("ob-chart", className)}><figcaption><strong>{title}</strong>{description ? <span>{description}</span> : null}</figcaption><svg viewBox="0 0 320 160" role="img" aria-label={`${title}. ${valueLabel}: ${summary}`} preserveAspectRatio="xMidYMid meet">{type === "bar" ? values.map((point, index) => <rect key={`${point.label}-${index}`} x={18 + index * (284 / Math.max(data.length, 1)) + 4} y={point.y} width={Math.max(4, 276 / Math.max(data.length, 1) - 8)} height={132 - point.y} rx="2" className="ob-chart-bar" />) : <polyline points={values.map((point) => `${point.x},${point.y}`).join(" ")} className="ob-chart-line" fill="none" />}{values.map((point, index) => <text key={`${point.label}-${index}`} x={point.x} y="151" textAnchor="middle" className="ob-chart-label">{point.label.slice(0, 8)}</text>)}</svg></figure>;
}
