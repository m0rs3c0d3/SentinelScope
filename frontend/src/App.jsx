import React, { useState, useEffect } from "react";
import { api } from "./utils/api";
import Header from "./components/Header";
import Footer from "./components/Footer";
import { ThreatIntelModule } from "./components/modules/threat-intel";
import NetScannerModule from "./components/modules/net-scanner/NetScannerModule";
import LogAnalyzerModule from "./components/modules/log-analyzer/LogAnalyzerModule";

export default function App() {
  const [activeModule, setActiveModule] = useState("threat-intel");
  const [serviceStatus, setServiceStatus] = useState(null);

  // Check backend health on mount
  useEffect(() => {
    const checkHealth = async () => {
      try {
        const data = await api.healthCheck();
        setServiceStatus({ connected: true, services: data.services, version: data.version });
      } catch {
        setServiceStatus({ connected: false, services: {}, version: null });
      }
    };
    checkHealth();

    // Re-check every 30s
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const renderModule = () => {
    switch (activeModule) {
      case "threat-intel":
        return <ThreatIntelModule />;
      case "net-scan":
        return <NetScannerModule />;
      case "log-analyzer":
        return <LogAnalyzerModule />;
      default:
        return <ThreatIntelModule />;
    }
  };

  return (
    <div style={{
      minHeight: "100vh", display: "flex", flexDirection: "column",
      background: "var(--bg-primary)", color: "var(--text-primary)",
    }}>
      <Header
        activeModule={activeModule}
        setActiveModule={setActiveModule}
        serviceStatus={serviceStatus}
      />

      <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
        {renderModule()}
      </div>

      <Footer serviceStatus={serviceStatus} />
    </div>
  );
}
