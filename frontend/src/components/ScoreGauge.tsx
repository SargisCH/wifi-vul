interface Props {
  score: number;
}

function scoreColor(score: number): string {
  if (score >= 80) return "#22c55e"; // green
  if (score >= 60) return "#f59e0b"; // amber
  if (score >= 40) return "#f97316"; // orange
  return "#ef4444"; // red
}

function scoreLabel(score: number): string {
  if (score >= 80) return "Good";
  if (score >= 60) return "Fair";
  if (score >= 40) return "Poor";
  return "Critical";
}

export default function ScoreGauge({ score }: Props) {
  const color = scoreColor(score);
  const label = scoreLabel(score);
  const circumference = 2 * Math.PI * 54;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center gap-2">
      <svg width="140" height="140" viewBox="0 0 140 140">
        <circle cx="70" cy="70" r="54" fill="none" stroke="#1e293b" strokeWidth="12" />
        <circle
          cx="70"
          cy="70"
          r="54"
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 70 70)"
          style={{ transition: "stroke-dashoffset 0.8s ease" }}
        />
        <text x="70" y="65" textAnchor="middle" fill={color} fontSize="28" fontWeight="bold" dominantBaseline="middle">
          {score}
        </text>
        <text x="70" y="90" textAnchor="middle" fill="#94a3b8" fontSize="13">
          / 100
        </text>
      </svg>
      <span className="text-sm font-semibold" style={{ color }}>{label}</span>
    </div>
  );
}
