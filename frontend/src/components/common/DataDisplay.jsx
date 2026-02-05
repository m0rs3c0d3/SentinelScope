import React, { useState } from "react";
import { getVerdictStyle } from "../../utils/helpers";

export function SourceCard({ title, icon, children }) {
  const [hovered, setHovered] = useState(false);

  return (
    <div
      style={{
        background: "var(--bg-secondary)",
        border: `1px solid ${hovered ? "var(--border-hover)" : "var(--border)"}`,
        borderRadius: 10,
        padding: "16px 18px",
        flex: "1 1 260px",
        minWidth: 260,
        backdropFilter: "blur(10px)",
        transition: "border-color 0.2s",
      }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
        <span style={{ fontSize: 14 }}>{icon}</span>
        <span style={{
          fontSize: 12, fontWeight: 700, textTransform: "uppercase",
          letterSpacing: 1.5, color: "var(--text-secondary)", fontFamily: "var(--font-mono)",
        }}>
          {title}
        </span>
      </div>
      {children}
    </div>
  );
}

export function DataRow({ label, value, color }) {
  return (
    <div style={{
      display: "flex", justifyContent: "space-between", alignItems: "center",
      padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.03)",
    }}>
      <span style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
        {label}
      </span>
      <span style={{
        fontSize: 12, color: color || "var(--text-primary)", fontFamily: "var(--font-mono)", fontWeight: 600,
      }}>
        {value ?? "N/A"}
      </span>
    </div>
  );
}

export function TagList({ tags }) {
  if (!tags || tags.length === 0) return null;

  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 6 }}>
      {tags.map((tag, i) => (
        <span key={i} style={{
          fontSize: 10, padding: "2px 8px", borderRadius: 20,
          background: "var(--cyan-dim)", color: "var(--cyan)",
          border: "1px solid var(--cyan-border)", fontFamily: "var(--font-mono)",
        }}>
          {tag}
        </span>
      ))}
    </div>
  );
}

export function VerdictBadge({ verdict }) {
  const vs = getVerdictStyle(verdict);

  return (
    <span style={{
      display: "inline-block", fontSize: 11, fontWeight: 700, padding: "4px 14px",
      borderRadius: 20, background: vs.bg, color: vs.color, border: `1px solid ${vs.border}`,
      fontFamily: "var(--font-mono)", letterSpacing: 1,
    }}>
      {verdict}
    </span>
  );
}
