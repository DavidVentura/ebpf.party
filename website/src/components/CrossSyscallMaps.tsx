import React from "react";

const VerticalFlowDiagram: React.FC = () => {
  return (
    <div className="">
      <svg viewBox="0 20 700 700" className="w-full">
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

        {/* --- OPEN SYSCALL SECTION --- */}
        <g transform="translate(200, 50)">
          {/* Main Block */}
          <rect
            width="250"
            height="210"
            rx="4"
            className="fill-slate-900/80 stroke-slate-500 stroke-1"
          />
          <text
            x="35"
            y="-15"
            textAnchor="middle"
            className="fill-slate-100 font-bold text-lg uppercase tracking-widest"
          >
            Open
          </text>

          {/* Internal TPs (Dotted Lines) */}
          <line
            x1="10"
            y1="70"
            x2="240"
            y2="70"
            className="stroke-slate-700 stroke-2"
            strokeDasharray="4 4"
          />
          <line
            x1="10"
            y1="140"
            x2="240"
            y2="140"
            className="stroke-slate-700 stroke-2"
            strokeDasharray="4 4"
          />

          {/* Section Labels */}
          <text
            x="125"
            y="45"
            textAnchor="middle"
            className="fill-slate-600 text-[9px] uppercase font-bold tracking-tighter"
          >
            Enter TP
          </text>
          <text
            x="125"
            y="115"
            textAnchor="middle"
            className="fill-slate-600 text-[9px] uppercase font-bold tracking-tighter"
          >
            Syscall
          </text>
          <text
            x="125"
            y="185"
            textAnchor="middle"
            className="fill-slate-600 text-[9px] uppercase font-bold tracking-tighter"
          >
            Exit TP
          </text>

          {/* Arrows to Tmp Map */}
          <path
            d="M 30 45 L -60 45"
            className="stroke-emerald-500/50 stroke-1"
            fill="none"
            markerEnd="url(#v-arrow-emerald)"
          />
          <path
            d="M 30 185 L -60 185"
            className="stroke-emerald-500/50 stroke-1"
            fill="none"
            markerEnd="url(#v-arrow-emerald)"
          />
        </g>

        {/* TMP MAP (Open) */}
        <g transform="translate(50, 50)">
          <rect
            width="90"
            height="210"
            rx="2"
            className="fill-emerald-500/5 stroke-emerald-500/40 stroke-1"
          />
          <text
            x="45"
            y="20"
            textAnchor="middle"
            className="fill-emerald-500/60 font-mono text-[9px]"
          >
            open_curr_fd
          </text>
        </g>

        {/* --- USERSPACE SECTION --- */}
        <g transform="translate(200, 320)">
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
        <g transform="translate(200, 460)">
          {/* Main Block */}
          <rect
            width="250"
            height="210"
            rx="4"
            className="fill-slate-900/80 stroke-slate-500 stroke-1"
          />
          <text
            x="35"
            y="-15"
            textAnchor="middle"
            className="fill-slate-100 font-bold text-lg uppercase tracking-widest"
          >
            Read
          </text>

          {/* Internal TPs (Dotted Lines) */}
          <line
            x1="10"
            y1="70"
            x2="240"
            y2="70"
            className="stroke-slate-700 stroke-2"
            strokeDasharray="4 4"
          />
          <line
            x1="10"
            y1="140"
            x2="240"
            y2="140"
            className="stroke-slate-700 stroke-2"
            strokeDasharray="4 4"
          />

          {/* Section Labels */}
          <text
            x="125"
            y="45"
            textAnchor="middle"
            className="fill-slate-600 text-[9px] uppercase font-bold tracking-tighter"
          >
            Enter TP
          </text>
          <text
            x="125"
            y="115"
            textAnchor="middle"
            className="fill-slate-600 text-[9px] uppercase font-bold tracking-tighter"
          >
            Syscall
          </text>
          <text
            x="125"
            y="185"
            textAnchor="middle"
            className="fill-slate-600 text-[9px] uppercase font-bold tracking-tighter"
          >
            Exit TP
          </text>

          {/* Connector from Userspace */}
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

          {/* Arrows to Tmp Map */}
          <path
            d="M 30 45 L -60 45"
            className="stroke-emerald-500/50 stroke-1"
            fill="none"
            markerEnd="url(#v-arrow-emerald)"
          />
          <path
            d="M 30 185 L -60 185"
            className="stroke-emerald-500/50 stroke-1"
            fill="none"
            markerEnd="url(#v-arrow-emerald)"
          />
        </g>

        {/* TMP MAP (Read) */}
        <g transform="translate(50, 460)">
          <rect
            width="90"
            height="210"
            rx="2"
            className="fill-emerald-500/5 stroke-emerald-500/40 stroke-1"
          />
          <text
            x="45"
            y="20"
            textAnchor="middle"
            className="fill-emerald-500/60 font-mono text-[9px]"
          >
            read_curr_fd
          </text>
        </g>

        {/* --- PERSISTENT MAP --- */}
        <g transform="translate(500, 190)">
          <rect
            width="100"
            height="340"
            rx="4"
            className="fill-blue-500/10 stroke-blue-400 stroke-2 stroke-dashed"
          />
          <text
            x="50"
            y="20"
            textAnchor="middle"
            className="fill-blue-400 text-[10px] tracking-widest"
          >
            interesting_fds
          </text>

          {/* Write from Open Exit */}
          <path
            d="M -50 50 L -10 50"
            className="stroke-blue-400/60 stroke-1"
            fill="none"
            markerEnd="url(#v-arrow-blue)"
          />

          {/* Read into Read Entry */}
          <path
            d="M -10 315 L -50 315"
            className="stroke-blue-400/60 stroke-1"
            fill="none"
            markerEnd="url(#v-arrow-blue)"
          />
        </g>

        {/* LEAK (Visual Extra) */}
        <g transform="translate(450, 750)">
          <path
            d="M 0 -100 Q 50 -100, 50 -50"
            className="stroke-red-500 stroke-1"
            strokeDasharray="3 3"
            fill="none"
            markerEnd="url(#v-arrow)"
          />
          <text
            x="55"
            y="-45"
            className="fill-red-400 font-bold text-[10px] italic"
          >
            LEAK
          </text>
        </g>
      </svg>
    </div>
  );
};

export default VerticalFlowDiagram;
