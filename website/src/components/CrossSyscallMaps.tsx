import React from "react";

interface SyscallBlockProps {
  title: string;
  translateX: number;
  translateY: number;
}

const SyscallBlock: React.FC<SyscallBlockProps> = ({
  title,
  translateX,
  translateY,
}) => {
  return (
    <g transform={`translate(${translateX}, ${translateY})`}>
      {/* Main Block */}
      <rect
        width="250"
        height="150"
        rx="4"
        className="stroke-slate-500 stroke-1"
        style={{ fill: "var(--color-code-bg)" }}
      />
      <text
        x="35"
        y="-15"
        textAnchor="middle"
        className="fill-slate-100 font-bold text-lg uppercase tracking-widest"
      >
        {title}
      </text>

      {/* Internal TPs (Dotted Lines) */}
      <line
        x1="10"
        y1="50"
        x2="240"
        y2="50"
        className="stroke-slate-700 stroke-2"
        strokeDasharray="4 4"
      />
      <line
        x1="10"
        y1="100"
        x2="240"
        y2="100"
        className="stroke-slate-700 stroke-2"
        strokeDasharray="4 4"
      />

      {/* Section Labels */}
      <text
        x="125"
        y="25"
        textAnchor="middle"
        className="fill-slate-300 text-[12px] uppercase font-bold"
      >
        Enter TP
      </text>
      <text
        x="125"
        y="75"
        textAnchor="middle"
        className="fill-slate-300 text-[12px] uppercase font-bold "
      >
        Syscall
      </text>
      <text
        x="125"
        y="125"
        textAnchor="middle"
        className="fill-slate-300 text-[12px] uppercase font-bold "
      >
        Exit TP
      </text>

      {/* Arrows to Tmp Map */}
      <path
        d="M 0 25 L -58 25"
        className="stroke-emerald-500/50 stroke-1"
        fill="none"
        markerEnd="url(#v-arrow-emerald)"
      />
      <text
        x="-25"
        y="20"
        textAnchor="middle"
        className="fill-emerald-500 font-mono text-[12px]"
      >
        store
      </text>
      <path
        d="M -58 125 L -3 125"
        className="stroke-emerald-500/50 stroke-1"
        fill="none"
        markerEnd="url(#v-arrow-emerald)"
      />
      <text
        x="-25"
        y="120"
        textAnchor="middle"
        className="fill-emerald-500 font-mono text-[12px]"
      >
        check
      </text>
    </g>
  );
};

const VerticalFlowDiagram: React.FC = () => {
  return (
    <div className="p-1" style={{ maxWidth: "45rem", margin: "0px auto" }}>
      <svg viewBox="35 20 570 540">
        <defs>
          <marker
            id="v-arrow"
            viewBox="0 0 10 10"
            refX="5"
            refY="5"
            markerWidth="5"
            markerHeight="5"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#94a3b8" />
          </marker>
          <marker
            id="v-arrow-blue"
            viewBox="0 0 10 10"
            refX="5"
            refY="5"
            markerWidth="5"
            markerHeight="5"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#3b82f6" />
          </marker>
          <marker
            id="v-arrow-emerald"
            viewBox="0 0 10 10"
            refX="5"
            refY="5"
            markerWidth="5"
            markerHeight="5"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#10b981" />
          </marker>
        </defs>

        <SyscallBlock title="Open" translateX={200} translateY={50} />

        <g transform="translate(40, 50)">
          <rect
            width="100"
            height="150"
            rx="2"
            className="fill-emerald-500/5 stroke-emerald-500/40 stroke-1"
          />
          <text
            x="50"
            y="20"
            textAnchor="middle"
            className="fill-emerald-500/90 font-mono text-[12px]"
          >
            open_curr_fd
          </text>
          <text
            x="50"
            y="70"
            textAnchor="middle"
            className="fill-emerald-500/70 font-mono text-[12px]"
          >
            <tspan x="50" dy="0">
              pid
            </tspan>
            <tspan x="50" dy="15">
              ⇊
            </tspan>
            <tspan x="50" dy="15">
              void
            </tspan>
          </text>
        </g>

        {/* --- USERSPACE SECTION --- */}
        <g transform="translate(200, 260)">
          <rect
            width="250"
            height="80"
            rx="4"
            className="fill-slate-800/50 stroke-slate-700 stroke-1"
          />
          <text
            x="125"
            y="45"
            textAnchor="middle"
            className="fill-white font-mono text-sm"
          >
            Userspace
          </text>

          {/* Connector from Open */}
          <path
            d="M 125 -60 L 125 -10"
            className="stroke-blue-400 stroke-2"
            fill="none"
            markerEnd="url(#v-arrow-blue)"
          />
          <text x="135" y="-35" className="fill-blue-400 font-mono text-[10px]">
            FD
          </text>
        </g>

        {/* --- READ SYSCALL SECTION --- */}
        <SyscallBlock title="Read" translateX={200} translateY={400} />

        {/* Connector from Userspace to Read */}
        <g transform="translate(200, 400)">
          <path
            d="M 125 -60 L 125 -10"
            className="stroke-emerald-400 stroke-2"
            fill="none"
            markerEnd="url(#v-arrow-emerald)"
          />
          <text
            x="135"
            y="-35"
            className="fill-emerald-400 font-mono text-[10px]"
          >
            FD, buf
          </text>
        </g>

        {/* TMP MAP (Read) */}
        <g transform="translate(40, 400)">
          <rect
            width="100"
            height="150"
            rx="2"
            className="fill-emerald-500/5 stroke-emerald-500/40 stroke-1"
          />
          <text
            x="50"
            y="20"
            textAnchor="middle"
            className="fill-emerald-500/90 font-mono text-[12px]"
          >
            read_curr_fd
          </text>
          <text
            x="50"
            y="70"
            textAnchor="middle"
            className="fill-emerald-500/70 font-mono text-[12px]"
          >
            <tspan x="50" dy="0">
              pid
            </tspan>
            <tspan x="50" dy="15">
              ⇊
            </tspan>
            <tspan x="50" dy="15">
              buf addr
            </tspan>
          </text>
        </g>

        {/* --- PERSISTENT MAP --- */}
        <g transform="translate(500, 140)">
          <rect
            width="100"
            height="290"
            rx="4"
            className="fill-blue-500/10 stroke-blue-400 stroke-1 stroke-dashed"
          />
          <text
            x="50"
            y="20"
            textAnchor="middle"
            className="fill-blue-400 text-[10px] tracking-widest"
          >
            interesting_fds
          </text>
          <text
            x="50"
            y="135"
            textAnchor="middle"
            className="fill-blue-400/70 font-mono text-[12px]"
          >
            <tspan x="50" dy="0">
              {"{pid, fd}"}
            </tspan>
            <tspan x="50" dy="15">
              ⇊
            </tspan>
            <tspan x="50" dy="15">
              void
            </tspan>
          </text>

          {/* Write from Open Exit */}
          <path
            d="M -50 40 L -5 40"
            className="stroke-blue-400/60 stroke-1"
            fill="none"
            markerEnd="url(#v-arrow-blue)"
          />
          <text
            x="-28"
            y="35"
            textAnchor="middle"
            className="fill-blue-400 font-mono text-[12px]"
          >
            store
          </text>

          {/* Read into Read Entry */}
          <path
            d="M 0 285 L -48 285"
            className="stroke-blue-400/60 stroke-1"
            fill="none"
            markerEnd="url(#v-arrow-blue)"
          />
          <text
            x="-24"
            y="280"
            textAnchor="middle"
            className="fill-blue-400 font-mono text-[12px]"
          >
            check
          </text>
        </g>
      </svg>
    </div>
  );
};

export default VerticalFlowDiagram;
