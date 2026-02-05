const API_BASE = "/api/v1";

class ApiClient {
  async get(path) {
    const res = await fetch(`${API_BASE}${path}`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    return res.json();
  }

  async post(path, body) {
    const res = await fetch(`${API_BASE}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    return res.json();
  }

  // Threat Intel
  async lookupIndicator(query, indicatorType = null) {
    const body = { query };
    if (indicatorType) body.indicator_type = indicatorType;
    return this.post("/threat-intel/lookup", body);
  }

  // Health
  async healthCheck() {
    return this.get("/health");
  }
}

export const api = new ApiClient();
