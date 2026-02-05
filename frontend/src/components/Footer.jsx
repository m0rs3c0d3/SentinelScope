import React from "react";

export default function Footer({ serviceStatus }) {
  const activeCount = serviceStatus
    ? Object.values(serviceStatus.services || {}).filter(Boolean).length
    : 0;

  return (
    <div style={{
      padding: "8px 24px", borderTop: "1px solid rgba(255,255,255,0.04)",
      display: "flex", justifyContent: "space-between", alignItems: "center",
      fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-mono)",
    }}>
      <span>SentinelScope v1.0 • Threat Intel Aggregator</span>
      <span>
        {serviceStatus
          ? `${activeCount}/4 API sources configured`
          : "Connecting to backend..."}
      </span>
    </div>
  );
}
