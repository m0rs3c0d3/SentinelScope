import React from "react";

export default function NetScannerModule() {
  return (
    <div style={{
      display: "flex", flexDirection: "column", alignItems: "center",
      justifyContent: "center", padding: "60px 20px", textAlign: "center", flex: 1,
    }}>
      <div style={{ fontSize: 48, marginBottom: 16, opacity: 0.4 }}>📡</div>
      <div style={{
        fontSize: 18, fontWeight: 700, color: "var(--text-primary)",
        fontFamily: "var(--font-mono)", marginBottom: 8,
      }}>
        Network Scanner
      </div>
      <div style={{ fontSize: 13, color: "var(--text-muted)", maxWidth: 400, lineHeight: 1.6 }}>
        Port scanning, service detection, OS fingerprinting, and network mapping. Coming in Module 2.
      </div>
      <div style={{
        marginTop: 20, padding: "8px 20px", borderRadius: 8,
        background: "var(--cyan-dim)", border: "1px solid var(--cyan-border)",
        color: "var(--cyan)", fontSize: 11, fontFamily: "var(--font-mono)", fontWeight: 600,
      }}>
        COMING SOON
      </div>
    </div>
  );
}
