import React from "react";

const MODULES = [
  { id: "threat-intel", label: "Threat Intel", icon: "🎯", active: true },
  { id: "net-scan", label: "Net Scanner", icon: "📡", active: false },
  { id: "log-analyzer", label: "Log Analyzer", icon: "📋", active: false },
];

export default function Header({ activeModule, setActiveModule, serviceStatus }) {
  return (
    <div style={{
      padding: "14px 24px", display: "flex", alignItems: "center", justifyContent: "space-between",
      borderBottom: "1px solid var(--border)", background: "rgba(10,14,23,0.95)",
      backdropFilter: "blur(20px)", position: "sticky", top: 0, zIndex: 100,
    }}>
      {/* Logo */}
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{
          width: 32, height: 32, borderRadius: 8, display: "flex", alignItems: "center",
          justifyContent: "center", background: "linear-gradient(135deg, #05d9e8 0%, #01579b 100%)",
          fontSize: 16, boxShadow: "0 0 20px rgba(5,217,232,0.3)",
        }}>⊕</div>
        <div>
          <span style={{
            fontSize: 16, fontWeight: 800, fontFamily: "var(--font-mono)",
            letterSpacing: -0.5, color: "var(--text-primary)",
          }}>
            Sentinel<span style={{ color: "var(--cyan)" }}>Scope</span>
          </span>
          <span style={{
            fontSize: 9, marginLeft: 8, padding: "2px 6px", borderRadius: 4,
            background: "var(--cyan-dim)", color: "var(--cyan)",
            fontFamily: "var(--font-mono)", fontWeight: 600,
          }}>v1.0</span>
        </div>
      </div>

      {/* Module tabs */}
      <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
        {MODULES.map((m) => (
          <button
            key={m.id}
            onClick={() => m.active && setActiveModule(m.id)}
            style={{
              padding: "6px 14px", borderRadius: 6, border: "1px solid",
              borderColor: activeModule === m.id ? "rgba(5,217,232,0.3)" : "transparent",
              background: activeModule === m.id ? "var(--cyan-dim)" : "transparent",
              color: activeModule === m.id ? "var(--cyan)" : "var(--text-muted)",
              cursor: m.active ? "pointer" : "default",
              fontSize: 12, fontWeight: 600, fontFamily: "var(--font-mono)",
              transition: "all 0.15s", display: "flex", alignItems: "center", gap: 6,
              opacity: m.active ? 1 : 0.5,
            }}
          >
            <span style={{ fontSize: 13 }}>{m.icon}</span> {m.label}
          </button>
        ))}

        {/* Service status indicator */}
        {serviceStatus && (
          <div style={{
            marginLeft: 12, display: "flex", alignItems: "center", gap: 4,
            fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-mono)",
          }}>
            <div style={{
              width: 6, height: 6, borderRadius: "50%",
              background: serviceStatus.connected ? "#05d9e8" : "#ff2a6d",
              boxShadow: serviceStatus.connected
                ? "0 0 6px rgba(5,217,232,0.5)"
                : "0 0 6px rgba(255,42,109,0.5)",
            }} />
            {serviceStatus.connected ? "API Connected" : "API Offline"}
          </div>
        )}
      </div>
    </div>
  );
}
