import type { ReactNode } from "react";

export function PageHeading({ eyebrow, title, description, actions }: { eyebrow: string; title: string; description: string; actions?: ReactNode }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>{actions && <div className="heading-actions">{actions}</div>}</div>;
}

export function Panel({ title, subtitle, tag, children, className = "" }: { title: string; subtitle?: string; tag?: string; children: ReactNode; className?: string }) {
  return <section className={`panel ${className}`}><div className="panel-heading"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>{tag && <span className="panel-tag">{tag}</span>}</div>{children}</section>;
}

export function StateTag({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "red" | "blue" | "green" | "amber" }) {
  return <span className={`state-tag state-${tone}`}><i />{children}</span>;
}

export function CodeLabel({ children }: { children: ReactNode }) {
  return <span className="code-label">{children}</span>;
}
