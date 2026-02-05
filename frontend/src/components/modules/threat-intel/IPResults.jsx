import React from "react";
import { RiskGauge, SourceCard, DataRow, TagList, VerdictBadge } from "../../common";

export default function IPResults({ data }) {
  const s = data.sources;

  return (
    <div className="animate-in">
      {/* Header */}
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        flexWrap: "wrap", gap: 16, marginBottom: 24,
      }}>
        <div>
          <div style={{
            fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase",
            letterSpacing: 1.5, fontFamily: "var(--font-mono)", marginBottom: 4,
          }}>Target</div>
          <div style={{
            fontSize: 24, fontWeight: 800, color: "var(--text-primary)", fontFamily: "var(--font-mono)",
          }}>{data.query}</div>
          <div style={{ marginTop: 8 }}>
            <VerdictBadge verdict={data.verdict} />
          </div>
        </div>
        <RiskGauge score={data.risk_score} />
      </div>

      {/* Source cards */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: 12 }}>
        {s.virustotal && (
          <SourceCard title="VirusTotal" icon="🛡️">
            <DataRow label="Detections" value={s.virustotal.detections} color={s.virustotal.score > 5 ? "var(--red)" : "var(--cyan)"} />
            <DataRow label="Reputation" value={s.virustotal.reputation} />
            <DataRow label="Category" value={s.virustotal.category} />
            <DataRow label="Last Seen" value={s.virustotal.last_seen} />
          </SourceCard>
        )}

        {s.abuseipdb && (
          <SourceCard title="AbuseIPDB" icon="🚨">
            <DataRow label="Abuse Score" value={`${s.abuseipdb.score}%`} color={s.abuseipdb.score > 50 ? "var(--red)" : "var(--cyan)"} />
            <DataRow label="Reports" value={s.abuseipdb.reports?.toLocaleString()} />
            <DataRow label="Confidence" value={`${s.abuseipdb.confidence}%`} />
            <DataRow label="ISP" value={s.abuseipdb.isp} />
            <DataRow label="Country" value={s.abuseipdb.country} />
            <DataRow label="Usage" value={s.abuseipdb.usage} />
          </SourceCard>
        )}

        {s.shodan && (
          <SourceCard title="Shodan" icon="🔍">
            <DataRow label="Open Ports" value={s.shodan.ports?.join(", ")} />
            <DataRow label="OS" value={s.shodan.os || "Unknown"} />
            <DataRow label="Organization" value={s.shodan.org} />
            <DataRow label="Services" value={s.shodan.services?.join(", ")} />
            {s.shodan.vulns?.length > 0 && (
              <DataRow label="Vulns" value={s.shodan.vulns.join(", ")} color="var(--red)" />
            )}
          </SourceCard>
        )}

        {s.otx && (
          <SourceCard title="AlienVault OTX" icon="👽">
            <DataRow label="Pulses" value={s.otx.pulses} color={s.otx.pulses > 20 ? "var(--orange)" : undefined} />
            <DataRow label="First Seen" value={s.otx.first_seen} />
            <DataRow label="Malware Samples" value={s.otx.malware_count} color={s.otx.malware_count > 0 ? "var(--red)" : "var(--cyan)"} />
            <TagList tags={s.otx.tags} />
          </SourceCard>
        )}
      </div>

      {/* Errors */}
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
