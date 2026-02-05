import React from "react";
import { getRiskColor } from "../../utils/helpers";

export default function GlowBar({ score }) {
  const color = getRiskColor(score);

  return (
    <div style={{
      width: "100%", height: 6, background: "rgba(255,255,255,0.05)",
      borderRadius: 3, overflow: "hidden",
    }}>
      <div style={{
        width: `${score}%`, height: "100%",
        background: `linear-gradient(90deg, ${color}88, ${color})`,
        borderRadius: 3, boxShadow: `0 0 12px ${color}66`,
        transition: "width 0.8s cubic-bezier(0.16,1,0.3,1)",
      }} />
    </div>
  );
}
