import React from "react";
import { getVerdictStyle } from "../../../utils/helpers";

function ScanHistoryItem({ item, onClick }) {
  const vs = getVerdictStyle(item.verdict);

  return (
    <button
      onClick={onClick}
      style={{
        width: "100%", background: "var(--bg-secondary)",
        border: "1px solid var(--border)", borderRadius: 8,
        padding: "10px 12px", cursor: "pointer", textAlign: "left",
        display: "flex", justifyContent: "space-between", alignItems: "center",
        transition: "all 0.15s",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.background = "var(--bg-hover)";
        e.currentTarget.style.borderColor = "var(--border-hover)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.background = "var(--bg-secondary)";
        e.currentTarget.style.borderColor = "var(--border)";
      }}
    >
      <div>
        <div style={{ fontSize: 12, color: "var(--text-primary)", fontFamily: "var(--font-mono)", fontWeight: 600 }}>
          {item.query}
        </div>
        <div style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginTop: 2 }}>
          {item.type} • {item.time}
        </div>
      </div>
      <span style={{
        fontSize: 9, fontWeight: 700, padding: "2px 8px", borderRadius: 12,
        background: vs.bg, color: vs.color, border: `1px solid ${vs.border}`,
        fontFamily: "var(--font-mono)",
      }}>
        {item.verdict}
      </span>
    </button>
  );
}

export default function ScanHistory({ history, onSelect }) {
  return (
    <div style={{
      width: 260, borderRight: "1px solid var(--border)", padding: "16px 12px",
      background: "rgba(255,255,255,0.01)", overflowY: "auto", flexShrink: 0,
    }}>
      <div style={{
        fontSize: 10, fontWeight: 700, textTransform: "uppercase",
        letterSpacing: 1.5, color: "var(--text-muted)", fontFamily: "var(--font-mono)",
        marginBottom: 12, padding: "0 4px",
      }}>
        Scan History ({history.length})
      </div>

      {history.length === 0 ? (
        <div style={{
          fontSize: 11, color: "var(--text-dim)", padding: "20px 4px",
          textAlign: "center", fontFamily: "var(--font-mono)",
        }}>
          No scans yet. Try an example query.
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {history.map((item, i) => (
            <ScanHistoryItem key={i} item={item} onClick={() => onSelect(item.query)} />
          ))}
        </div>
      )}
    </div>
  );
}
