import React, { useRef } from "react";
import { detectIndicatorType } from "../../../utils/helpers";

const EXAMPLES = [
  { label: "Google DNS", value: "8.8.8.8" },
  { label: "Tor Exit Node", value: "185.220.101.34" },
  { label: "Cloudflare IP", value: "104.26.10.78" },
  { label: "Nmap Scanme", value: "45.33.32.156" },
  { label: "EICAR Hash", value: "44d88612fea8a8f36de82e1278abb02f" },
  { label: "example.com", value: "example.com" },
];

export default function SearchBar({ query, setQuery, onSearch, loading }) {
  const inputRef = useRef(null);
  const detectedType = detectIndicatorType(query.trim());

  const handleKeyDown = (e) => {
    if (e.key === "Enter") onSearch();
  };

  return (
    <div style={{ maxWidth: 800, margin: "0 auto 32px" }}>
      {/* Input row */}
      <div style={{
        display: "flex", gap: 8, padding: 4,
        background: "var(--bg-secondary)", border: "1px solid rgba(255,255,255,0.08)",
        borderRadius: 12,
      }}>
        <div style={{ position: "relative", flex: 1, display: "flex", alignItems: "center" }}>
          <span style={{ position: "absolute", left: 14, fontSize: 16, opacity: 0.4 }}>⌕</span>
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Enter IP, domain, or file hash..."
            style={{
              width: "100%", padding: "14px 14px 14px 42px", background: "transparent",
              border: "none", color: "var(--text-primary)", fontSize: 14,
              fontFamily: "var(--font-mono)", outline: "none",
            }}
          />
          {detectedType && (
            <span style={{
              position: "absolute", right: 12, fontSize: 10, padding: "2px 8px",
              borderRadius: 4, background: "var(--cyan-dim)", color: "var(--cyan)",
              fontFamily: "var(--font-mono)", fontWeight: 600,
            }}>
              {detectedType}
            </span>
          )}
        </div>
        <button
          onClick={onSearch}
          disabled={loading || !detectedType}
          style={{
            padding: "12px 24px", borderRadius: 8, border: "none",
            background: detectedType
              ? "linear-gradient(135deg, var(--cyan), #01579b)"
              : "rgba(255,255,255,0.05)",
            color: detectedType ? "#fff" : "var(--text-dim)",
            cursor: detectedType ? "pointer" : "default",
            fontSize: 13, fontWeight: 700, fontFamily: "var(--font-mono)",
            transition: "all 0.2s", opacity: loading ? 0.6 : 1,
          }}
        >
          {loading ? "Scanning..." : "Analyze"}
        </button>
      </div>

      {/* Example queries */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 12, justifyContent: "center" }}>
        {EXAMPLES.map((eq) => (
          <button
            key={eq.value}
            onClick={() => { setQuery(eq.value); inputRef.current?.focus(); }}
            style={{
              padding: "4px 10px", borderRadius: 6, border: "1px solid var(--border)",
              background: "var(--bg-secondary)", color: "var(--text-secondary)",
              cursor: "pointer", fontSize: 10, fontFamily: "var(--font-mono)",
              transition: "all 0.15s",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.borderColor = "var(--border-hover)";
              e.currentTarget.style.color = "var(--cyan)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.borderColor = "var(--border)";
              e.currentTarget.style.color = "var(--text-secondary)";
            }}
          >
            {eq.label}
          </button>
        ))}
      </div>
    </div>
  );
}
