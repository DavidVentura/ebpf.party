import styles from "./ExecveArgs.module.css";

interface ArgValue {
  name: string;
  pointsTo?: string;
  isNull?: boolean;
}

interface ArgsEntry {
  index: number;
  name: string;
  subtitle?: string;
  isSimplePointer?: boolean;
  simpleValue?: string;
  arrayValues?: ArgValue[];
}

interface ExecveArgsProps {
  label: string;
  args: ArgsEntry[];
}

export default function ExecveArgs({ args }: ExecveArgsProps) {
  const argBoxWidth = 100;
  const argBoxHeight = 50;
  const argBoxGap = 5;
  const arrowHeight = 50;
  const valueBoxWidth = 90;
  const valueBoxHeight = 40;
  const valueBoxGap = 5;
  const secondArrowHeight = 25;
  const finalBoxWidth = valueBoxWidth;
  const finalBoxHeight = 30;
  const padding = 1;
  const subGroupGap = 30;

  const truncateText = (text: string, maxChars: number = 10) => {
    if (text.length <= maxChars) return text;
    return text.substring(0, maxChars - 1) + "…";
  };

  const calculateSubGroupWidth = (arg: ArgsEntry) => {
    if (arg.isSimplePointer) return argBoxWidth;
    if (arg.arrayValues) {
      return Math.max(
        argBoxWidth,
        arg.arrayValues.length * (valueBoxWidth + valueBoxGap) - valueBoxGap
      );
    }
    return argBoxWidth;
  };

  const subGroupWidths = args.map(calculateSubGroupWidth);
  const totalWidth =
    subGroupWidths.reduce((a, b) => a + b, 0) +
    (args.length - 1) * subGroupGap +
    padding * 2;

  const totalHeight =
    argBoxHeight +
    arrowHeight +
    valueBoxHeight +
    secondArrowHeight +
    finalBoxHeight +
    padding * 2;

  const argsStartX = 2;

  return (
    <div className={styles.container}>
      <svg width={totalWidth} height={totalHeight} className={styles.svg}>
        <defs>
          <marker
            id="arrowhead-execve"
            markerWidth="4"
            markerHeight="4"
            refX="4"
            refY="2"
            orient="auto"
          >
            <polygon points="0 0, 4 2, 0 4" fill="#3b82f6" />
          </marker>
        </defs>

        {/* Args row - packed together */}
        {args.map((arg, i) => {
          const argX = argsStartX + i * (argBoxWidth + argBoxGap);
          const argCenterX = argX + argBoxWidth / 2;

          return (
            <g key={`arg-${arg.index}`}>
              <rect
                x={argX}
                y={padding}
                width={argBoxWidth}
                height={argBoxHeight}
                fill="white"
                stroke="#3b82f6"
                strokeWidth="2"
              />

              <text
                x={argCenterX}
                y={padding + argBoxHeight / 2 - (arg.subtitle ? 4 : 0)}
                textAnchor="middle"
                alignmentBaseline="central"
                fontSize="14"
                fontWeight="bold"
                fill="#374151"
              >
                {arg.name}
              </text>

              {arg.subtitle && (
                <text
                  x={argCenterX}
                  y={padding + argBoxHeight / 2 + 12}
                  textAnchor="middle"
                  alignmentBaseline="central"
                  fontSize="11"
                  fill="#6b7280"
                >
                  {arg.subtitle}
                </text>
              )}
            </g>
          );
        })}

        {/* Sub-groups - spread out */}
        {args.map((arg, i) => {
          const subGroupX =
            subGroupWidths.slice(0, i).reduce((a, b) => a + b, 0) +
            i * subGroupGap +
            padding;
          const subGroupWidth = subGroupWidths[i];

          const argCenterX =
            argsStartX + i * (argBoxWidth + argBoxGap) + argBoxWidth / 2;

          const firstElementX = arg.isSimplePointer
            ? subGroupX + subGroupWidth / 2
            : subGroupX + valueBoxWidth / 2;

          return (
            <g key={`subgroup-${arg.index}`}>
              {/* Arrow from args box to first element */}
              <line
                x1={argCenterX}
                y1={argBoxHeight + padding}
                x2={firstElementX}
                y2={argBoxHeight + arrowHeight + padding}
                stroke="#3b82f6"
                strokeWidth="2"
                markerEnd="url(#arrowhead-execve)"
              />

              {/* Simple pointer (args[0] -> filename) */}
              {arg.isSimplePointer && arg.simpleValue && (
                <>
                  <rect
                    x={subGroupX}
                    y={argBoxHeight + arrowHeight + padding}
                    width={subGroupWidth}
                    height={finalBoxHeight}
                    fill="white"
                    stroke="#d1d5db"
                    strokeWidth="1"
                    rx="3"
                  />

                  <text
                    x={subGroupX + subGroupWidth / 2}
                    y={
                      argBoxHeight +
                      arrowHeight +
                      finalBoxHeight / 2 +
                      padding +
                      5
                    }
                    textAnchor="middle"
                    fontSize="13"
                    fontFamily="monospace"
                    fill="#374151"
                  >
                    {truncateText(arg.simpleValue, 11)}
                  </text>
                </>
              )}

              {/* Array of pointers (args[1] -> argv[], args[2] -> envp[]) */}
              {arg.arrayValues && (
                <>
                  {/* Array boxes */}
                  {arg.arrayValues.map((val, j) => {
                    const valX = subGroupX + j * (valueBoxWidth + valueBoxGap);
                    const valCenterX = valX + valueBoxWidth / 2;
                    const valY = argBoxHeight + arrowHeight + padding;

                    return (
                      <g key={j}>
                        <rect
                          x={valX}
                          y={valY}
                          width={valueBoxWidth}
                          height={valueBoxHeight}
                          fill="white"
                          stroke={val.isNull ? "#9ca3af" : "#3b82f6"}
                          strokeWidth="2"
                          strokeDasharray={val.isNull ? "5,5" : "0"}
                          opacity={val.isNull ? 0.7 : 1}
                        />

                        <text
                          x={valCenterX}
                          y={valY + valueBoxHeight / 2 + 4}
                          textAnchor="middle"
                          alignmentBaseline="central"
                          fontSize="12"
                          fontWeight="bold"
                          fill={val.isNull ? "#6b7280" : "#374151"}
                        >
                          {val.name}
                        </text>

                        {/* String values */}
                        {val.pointsTo && (
                          <>
                            <line
                              x1={valCenterX}
                              y1={valY + valueBoxHeight}
                              x2={valCenterX}
                              y2={valY + valueBoxHeight + secondArrowHeight}
                              stroke="#3b82f6"
                              strokeWidth="2"
                              markerEnd="url(#arrowhead-execve)"
                            />

                            <rect
                              x={valX + (valueBoxWidth - finalBoxWidth) / 2}
                              y={valY + valueBoxHeight + secondArrowHeight}
                              width={finalBoxWidth}
                              height={finalBoxHeight}
                              fill="white"
                              stroke="#d1d5db"
                              strokeWidth="1"
                              rx="3"
                            />

                            <text
                              x={valCenterX}
                              y={
                                valY +
                                valueBoxHeight +
                                secondArrowHeight +
                                finalBoxHeight / 2 +
                                5
                              }
                              textAnchor="middle"
                              fontSize="11"
                              fontFamily="monospace"
                              fill="#374151"
                            >
                              {truncateText(val.pointsTo, 12)}
                            </text>
                          </>
                        )}
                      </g>
                    );
                  })}
                </>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
