export function getRiskColor(score) {
  if (score >= 75) return "var(--red)";
  if (score >= 40) return "var(--orange)";
  if (score >= 15) return "var(--yellow)";
  return "var(--cyan)";
}

export function getVerdictStyle(verdict) {
  const map = {
    MALICIOUS: { color: "var(--red)", bg: "rgba(255,42,109,0.12)", border: "rgba(255,42,109,0.3)" },
    SUSPICIOUS: { color: "var(--orange)", bg: "rgba(255,158,44,0.12)", border: "rgba(255,158,44,0.3)" },
    BENIGN: { color: "var(--cyan)", bg: "rgba(5,217,232,0.12)", border: "rgba(5,217,232,0.3)" },
    UNKNOWN: { color: "var(--text-secondary)", bg: "rgba(138,143,152,0.12)", border: "rgba(138,143,152,0.3)" },
  };
  return map[verdict] || map.UNKNOWN;
}

export function detectIndicatorType(query) {
  const q = query.trim();
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(q)) return "IP";
  if (/^[a-fA-F0-9]{32}$/.test(q) || /^[a-fA-F0-9]{40}$/.test(q) || /^[a-fA-F0-9]{64}$/.test(q)) return "Hash";
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$/.test(q)) return "Domain";
  return null;
}
