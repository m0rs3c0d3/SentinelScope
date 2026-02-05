import React from "react";

export function EmptyState() {
  const sources = [
    { icon: "🛡️", label: "VirusTotal", desc: "AV detections" },
    { icon: "🚨", label: "AbuseIPDB", desc: "Abuse reports" },
    { icon: "🔍", label: "Shodan", desc: "Port & service data" },
    { icon: "👽", label: "AlienVault OTX", desc: "Pulse intelligence" },
  ];

  return (
    <div style={{ maxWidth: 600, margin: "40px auto", textAlign: "center" }}>
      <div style={{ fontSize: 64, marginBottom: 16, opacity: 0.15 }}>🎯</div>
      <div style={{
        fontSize: 20, fontWeight: 700, color: "var(--text-primary)",
        fontFamily: "var(--font-mono)", marginBottom: 8,
      }}>
        Threat Intelligence Aggregator
      </div>
      <div style={{ fontSize: 13, color: "var(--text-muted)", lineHeight: 1.6, marginBottom: 24 }}>
        Query IPs, domains, and file hashes across multiple threat intelligence feeds.
        Results are aggregated and scored with a unified risk assessment.
      </div>
      <div style={{
        display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 10,
        padding: 20, background: "var(--bg-secondary)", borderRadius: 12,
        border: "1px solid rgba(255,255,255,0.05)",
      }}>
        {sources.map((s) => (
          <div key={s.label} style={{ padding: 12, textAlign: "center" }}>
            <div style={{ fontSize: 24, marginBottom: 6 }}>{s.icon}</div>
            <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-primary)", fontFamily: "var(--font-mono)" }}>
              {s.label}
            </div>
            <div style={{ fontSize: 10, color: "var(--text-muted)" }}>{s.desc}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function NotFoundState({ indicatorType }) {
  return (
    <div style={{ maxWidth: 800, margin: "0 auto", textAlign: "center", padding: 40 }}>
      <div style={{ fontSize: 48, marginBottom: 12, opacity: 0.3 }}>🔎</div>
      <div style={{ fontSize: 14, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
        No threat data found for this {indicatorType?.toLowerCase() || "indicator"}.
      </div>
      <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 8, fontFamily: "var(--font-mono)" }}>
        The indicator may be too new, or the configured API sources returned no results.
      </div>
    </div>
  );
}
