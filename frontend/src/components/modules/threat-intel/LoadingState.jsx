import React from "react";

const SOURCES = ["VirusTotal", "AbuseIPDB", "Shodan", "OTX"];

export default function LoadingState() {
  return (
    <div style={{ maxWidth: 800, margin: "0 auto", textAlign: "center", padding: 40 }}>
      <div style={{ display: "flex", justifyContent: "center", gap: 16, marginBottom: 20 }}>
        {SOURCES.map((s, i) => (
          <div
            key={s}
            style={{
              padding: "8px 14px", borderRadius: 8,
              background: "var(--cyan-dim)", border: "1px solid var(--cyan-border)",
              fontSize: 11, color: "var(--cyan)", fontFamily: "var(--font-mono)",
              animation: `pulse 1.5s ease ${i * 0.2}s infinite`,
            }}
          >
            {s}
          </div>
        ))}
      </div>
      <div style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
        Querying threat intelligence sources...
      </div>
    </div>
  );
}
