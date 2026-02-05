import React from "react";
import { getRiskColor } from "../../utils/helpers";

export default function RiskGauge({ score }) {
  const color = getRiskColor(score);
  const angle = (score / 100) * 180 - 90;

  return (
    <div style={{ position: "relative", width: 140, height: 80, margin: "0 auto" }}>
      <svg viewBox="0 0 140 80" style={{ width: "100%", height: "100%" }}>
        <path
          d="M 10 75 A 60 60 0 0 1 130 75"
          fill="none"
          stroke="rgba(255,255,255,0.06)"
          strokeWidth="8"
          strokeLinecap="round"
        />
        <path
          d="M 10 75 A 60 60 0 0 1 130 75"
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={`${(score / 100) * 188} 188`}
          style={{
            filter: `drop-shadow(0 0 6px ${color}88)`,
            transition: "stroke-dasharray 1s cubic-bezier(0.16,1,0.3,1)",
          }}
        />
        <line
          x1="70" y1="75"
          x2={70 + 40 * Math.cos((angle * Math.PI) / 180)}
          y2={75 + 40 * Math.sin((angle * Math.PI) / 180)}
          stroke={color} strokeWidth="2" strokeLinecap="round"
          style={{
            transition: "all 1s cubic-bezier(0.16,1,0.3,1)",
            filter: `drop-shadow(0 0 4px ${color})`,
          }}
        />
        <circle cx="70" cy="75" r="4" fill={color} style={{ filter: `drop-shadow(0 0 6px ${color})` }} />
      </svg>
      <div style={{
        position: "absolute", bottom: -4, left: "50%", transform: "translateX(-50%)", textAlign: "center",
      }}>
        <div style={{
          fontSize: 28, fontWeight: 800, color, fontFamily: "var(--font-mono)",
          textShadow: `0 0 20px ${color}44`,
        }}>
          {score}
        </div>
      </div>
    </div>
  );
}
