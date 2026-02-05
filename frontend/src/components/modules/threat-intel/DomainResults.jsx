import React from "react";
import { RiskGauge, SourceCard, DataRow, TagList, VerdictBadge } from "../../common";

export default function DomainResults({ data }) {
  const s = data.sources;

  return (
    <div className="animate-in">
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        flexWrap: "wrap", gap: 16, marginBottom: 24,
      }}>
        <div>
          <div style={{
            fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase",
            letterSpacing: 1.5, fontFamily: "var(--font-mono)", marginBottom: 4,
          }}>Domain</div>
          <div style={{
            fontSize: 24, fontWeight: 800, color: "var(--text-primary)", fontFamily: "var(--font-mono)",
          }}>{data.query}</div>
          <div style={{ marginTop: 8 }}>
            <VerdictBadge verdict={data.verdict} />
          </div>
        </div>
        <RiskGauge score={data.risk_score} />
      </div>

      <div style={{ display: "flex", flexWrap: "wrap", gap: 12 }}>
        {s.virustotal && (
          <SourceCard title="VirusTotal" icon="🛡️">
            <DataRow label="Detections" value={s.virustotal.detections} />
            <DataRow label="Reputation" value={s.virustotal.reputation} />
            <DataRow label="Category" value={s.virustotal.category} />
            <DataRow label="Registrar" value={s.virustotal.registrar} />
          </SourceCard>
        )}

        {s.otx && (
          <SourceCard title="AlienVault OTX" icon="👽">
            <DataRow label="Pulses" value={s.otx.pulses} />
            <DataRow label="Malware Samples" value={s.otx.malware_count} />
            <TagList tags={s.otx.tags} />
          </SourceCard>
        )}
      </div>

      {Object.keys(data.errors || {}).length > 0 && (
        <div style={{
          marginTop: 16, padding: "10px 14px", borderRadius: 8,
          background: "rgba(255,158,44,0.06)", border: "1px solid rgba(255,158,44,0.15)",
        }}>
          <div style={{ fontSize: 11, color: "var(--orange)", fontFamily: "var(--font-mono)", fontWeight: 600, marginBottom: 4 }}>
            ⚠ Some sources returned errors:
          </div>
          {Object.entries(data.errors).map(([src, err]) => (
            <div key={src} style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
              {src}: {err}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
