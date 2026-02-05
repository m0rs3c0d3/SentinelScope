import React, { useState } from "react";
import { api } from "../../../utils/api";
import { detectIndicatorType } from "../../../utils/helpers";
import SearchBar from "./SearchBar";
import IPResults from "./IPResults";
import HashResults from "./HashResults";
import DomainResults from "./DomainResults";
import ScanHistory from "./ScanHistory";
import LoadingState from "./LoadingState";
import { EmptyState, NotFoundState } from "./EmptyStates";

export default function ThreatIntelModule() {
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);

  const handleSearch = async () => {
    const trimmed = query.trim();
    if (!trimmed) return;

    const type = detectIndicatorType(trimmed);
    if (!type) return;

    setLoading(true);
    setResults(null);
    setError(null);

    try {
      const data = await api.lookupIndicator(trimmed);
      setResults(data);

      // Add to history
      const now = new Date();
      setHistory((prev) => [
        {
          query: trimmed,
          type: data.indicator_type?.toUpperCase() || type,
          verdict: data.verdict,
          time: now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        },
        ...prev.slice(0, 19),
      ]);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleHistorySelect = (q) => {
    setQuery(q);
  };

  const renderResults = () => {
    if (!results) return null;

    // Check if all sources returned null/empty
    const s = results.sources;
    const hasData = s.virustotal || s.abuseipdb || s.shodan || s.otx;
    if (!hasData) return <NotFoundState indicatorType={results.indicator_type} />;

    switch (results.indicator_type) {
      case "ip":
        return <IPResults data={results} />;
      case "hash":
        return <HashResults data={results} />;
      case "domain":
        return <DomainResults data={results} />;
      default:
        return <NotFoundState indicatorType={results.indicator_type} />;
    }
  };

  return (
    <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
      <ScanHistory history={history} onSelect={handleHistorySelect} />

      <div style={{ flex: 1, overflowY: "auto", padding: "24px 32px" }}>
        <SearchBar query={query} setQuery={setQuery} onSearch={handleSearch} loading={loading} />

        {loading && <LoadingState />}

        {error && (
          <div style={{
            maxWidth: 800, margin: "0 auto", padding: "16px 20px", borderRadius: 10,
            background: "rgba(255,42,109,0.06)", border: "1px solid rgba(255,42,109,0.15)",
          }}>
            <div style={{ fontSize: 12, color: "var(--red)", fontFamily: "var(--font-mono)", fontWeight: 600 }}>
              ⚠ Error
            </div>
            <div style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginTop: 4 }}>
              {error}
            </div>
          </div>
        )}

        {!loading && !error && results && (
          <div style={{ maxWidth: 900, margin: "0 auto" }}>{renderResults()}</div>
        )}

        {!loading && !error && !results && <EmptyState />}
      </div>
    </div>
  );
}
