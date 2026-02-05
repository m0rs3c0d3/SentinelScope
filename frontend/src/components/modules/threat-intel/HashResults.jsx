import React from "react";
import { RiskGauge, SourceCard, DataRow, TagList, VerdictBadge } from "../../common";

export default function HashResults({ data }) {
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
          }}>File Hash</div>
          <div style={{
            fontSize: 16, fontWeight: 800, color: "var(--text-primary)",
            fontFamily: "var(--font-mono)", wordBreak: "break-all",
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
            <DataRow label="Detections" value={s.virustotal.detections} color={s.virustotal.score > 5 ? "var(--red)" : "var(--cyan)"} />
            <DataRow label="File Name" value={s.virustotal.name} />
            <DataRow label="File Size" value={s.virustotal.size} />
            <DataRow label="File Type" value={s.virustotal.file_type} />
            <DataRow label="First Submitted" value={s.virustotal.first_submission} />
          </SourceCard>
        )}

        {s.otx && (
          <SourceCard title="AlienVault OTX" icon="👽">
            <DataRow label="Pulses" value={s.otx.pulses} />
            <DataRow label="Malware Family" value={s.otx.malware_family || "None"} color={s.otx.malware_family ? "var(--red)" : "var(--cyan)"} />
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
