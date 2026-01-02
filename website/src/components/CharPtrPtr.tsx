import styles from "./CharPtrPtr.module.css";

interface PointerEntry {
  index: number;
  name: string;
  pointsTo?: string;
  isNull?: boolean;
}

interface CharPtrPtrProps {
  label: string;
  pointers: PointerEntry[];
}

export default function CharPtrPtr({ label, pointers }: CharPtrPtrProps) {
  const boxWidth = 90;
  const boxHeight = 50;
  const boxGap = 4;
  const arrowHeight = 30;
  const valueBoxHeight = 30;
  const padding = 1;

  const totalWidth =
    pointers.length * (boxWidth + boxGap) - boxGap + padding * 2;
  const totalHeight =
    boxHeight + arrowHeight + valueBoxHeight + 20 + padding * 2;

  return (
    <div className={styles.container}>
      {label && <div className={styles.typeLabel}>{label}</div>}

      <svg width={totalWidth} height={totalHeight} className={styles.svg}>
        <defs>
          <marker
            id="arrowhead"
            markerWidth="4"
            markerHeight="4"
            refX="4"
            refY="2"
            orient="auto"
          >
            <polygon points="0 0, 4 2, 0 4" fill="#3b82f6" />
          </marker>
        </defs>

        {pointers.map((entry, i) => {
          const x = i * (boxWidth + boxGap) + padding;
          const boxCenterX = x + boxWidth / 2;
          const boxCenterY = padding + boxHeight / 2;

          return (
            <g key={entry.index}>
              <rect
                x={x}
                y={padding}
                width={boxWidth}
                height={boxHeight}
                fill="white"
                stroke={entry.isNull ? "#9ca3af" : "#3b82f6"}
                strokeWidth="2"
                strokeDasharray={entry.isNull ? "5,5" : "0"}
                opacity={entry.isNull ? 0.7 : 1}
              />

              <text
                x={boxCenterX}
                y={boxCenterY + 4} // stroke
                textAnchor="middle"
                alignmentBaseline="central"
                fontSize="14"
                fontWeight="bold"
                fill={entry.isNull ? "#6b7280" : "#374151"}
              >
                {entry.name}
              </text>

              {entry.pointsTo && (
                <>
                  <line
                    x1={boxCenterX}
                    y1={boxHeight + padding}
                    x2={boxCenterX}
                    y2={boxHeight + arrowHeight + padding}
                    stroke="#3b82f6"
                    strokeWidth="2"
                    markerEnd="url(#arrowhead)"
                  />

                  <rect
                    x={x}
                    y={boxHeight + arrowHeight + padding}
                    width={boxWidth}
                    height={valueBoxHeight}
                    fill="white"
                    stroke="#d1d5db"
                    strokeWidth="1"
                    rx="3"
                  />

                  <text
                    x={boxCenterX}
                    y={
                      boxHeight + arrowHeight + valueBoxHeight / 2 + 5 + padding
                    }
                    textAnchor="middle"
                    fontSize="13"
                    fontFamily="monospace"
                    fill="#374151"
                  >
                    {entry.pointsTo}
                  </text>
                </>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
