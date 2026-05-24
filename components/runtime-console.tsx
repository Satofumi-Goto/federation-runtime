"use client";

import { motion } from "framer-motion";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  RadialBar,
  RadialBarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import ReactFlow, {
  Background,
  BackgroundVariant,
  Controls,
  MarkerType,
  MiniMap,
  Position,
  type Edge,
  type Node,
} from "@xyflow/react";

const palette = {
  bg: "#070B12",
  card: "#101827",
  border: "#1F2A3D",
  cyan: "#35D0FF",
  green: "#5CFFB1",
  amber: "#FFCC66",
  red: "#FF5F7A",
  violet: "#9D7BFF",
  muted: "#6F7F99",
};

const executionSeries = [
  { t: "15:00", a: 42, b: 14, c: 22 },
  { t: "15:02", a: 54, b: 17, c: 26 },
  { t: "15:04", a: 46, b: 24, c: 18 },
  { t: "15:06", a: 69, b: 22, c: 31 },
  { t: "15:08", a: 63, b: 30, c: 24 },
  { t: "15:10", a: 78, b: 29, c: 39 },
  { t: "15:12", a: 72, b: 35, c: 34 },
];

const collapseBands = [
  { zone: "R1", value: 34 },
  { zone: "R2", value: 62 },
  { zone: "R3", value: 48 },
  { zone: "R4", value: 79 },
  { zone: "R5", value: 57 },
  { zone: "R6", value: 43 },
  { zone: "R7", value: 71 },
  { zone: "R8", value: 52 },
];

const telemetryFlux = [
  { t: "15:00", latency: 18, pressure: 42, quorum: 94 },
  { t: "15:02", latency: 22, pressure: 39, quorum: 92 },
  { t: "15:04", latency: 29, pressure: 51, quorum: 91 },
  { t: "15:06", latency: 25, pressure: 64, quorum: 88 },
  { t: "15:08", latency: 31, pressure: 59, quorum: 89 },
  { t: "15:10", latency: 27, pressure: 67, quorum: 86 },
  { t: "15:12", latency: 24, pressure: 53, quorum: 90 },
];

const runtimeSlices = [
  { name: "federated", value: 74, fill: palette.green },
  { name: "isolated", value: 17, fill: palette.amber },
  { name: "quarantined", value: 9, fill: palette.red },
];

const knowledgeNodes: Node[] = [
  {
    id: "obsidian",
    position: { x: 260, y: 28 },
    data: { label: <GraphLabel title="OBSIDIAN VAULT" sub="247 runtime notes" accent={palette.violet} /> },
    sourcePosition: Position.Bottom,
    style: nodeStyle(palette.violet),
  },
  {
    id: "control",
    position: { x: 248, y: 155 },
    data: { label: <GraphLabel title="FEDERATION CONTROL" sub="policy + topology" accent={palette.cyan} /> },
    targetPosition: Position.Top,
    sourcePosition: Position.Bottom,
    style: nodeStyle(palette.cyan),
  },
  {
    id: "transit",
    position: { x: 44, y: 274 },
    data: { label: <GraphLabel title="TRANSIT MESH" sub="rail / bus dependencies" accent={palette.green} /> },
    targetPosition: Position.Right,
    sourcePosition: Position.Right,
    style: nodeStyle(palette.green),
  },
  {
    id: "energy",
    position: { x: 248, y: 304 },
    data: { label: <GraphLabel title="ENERGY GRID" sub="substation telemetry" accent={palette.amber} /> },
    targetPosition: Position.Top,
    sourcePosition: Position.Right,
    style: nodeStyle(palette.amber),
  },
  {
    id: "water",
    position: { x: 470, y: 270 },
    data: { label: <GraphLabel title="WATER OPS" sub="pressure + pump graph" accent={palette.cyan} /> },
    targetPosition: Position.Left,
    style: nodeStyle(palette.cyan),
  },
  {
    id: "risk",
    position: { x: 122, y: 430 },
    data: { label: <GraphLabel title="COLLAPSE INDEX" sub="cascade constraints" accent={palette.red} /> },
    targetPosition: Position.Top,
    style: nodeStyle(palette.red),
  },
  {
    id: "mutual-aid",
    position: { x: 414, y: 430 },
    data: { label: <GraphLabel title="MUTUAL AID" sub="cross-city runtime pact" accent={palette.green} /> },
    targetPosition: Position.Top,
    style: nodeStyle(palette.green),
  },
];

const knowledgeEdges: Edge[] = [
  edge("obsidian", "control", "semantic links"),
  edge("control", "transit", "depends_on"),
  edge("control", "energy", "governs"),
  edge("control", "water", "governs"),
  edge("transit", "risk", "cascade path"),
  edge("energy", "risk", "load shed"),
  edge("water", "mutual-aid", "reserve"),
  edge("energy", "mutual-aid", "export"),
];

const runtimeNodes: Node[] = [
  {
    id: "core",
    position: { x: 245, y: 45 },
    data: { label: <GraphLabel title="URBAN OS CORE" sub="quorum 90% | drift 0.18" accent={palette.cyan} /> },
    sourcePosition: Position.Bottom,
    style: nodeStyle(palette.cyan),
  },
  {
    id: "north",
    position: { x: 42, y: 196 },
    data: { label: <GraphLabel title="NORTH CELL" sub="p95 24ms | sync 0.97" accent={palette.green} /> },
    targetPosition: Position.Right,
    sourcePosition: Position.Right,
    style: nodeStyle(palette.green),
  },
  {
    id: "harbor",
    position: { x: 250, y: 198 },
    data: { label: <GraphLabel title="HARBOR CELL" sub="p95 31ms | surge 0.61" accent={palette.amber} /> },
    targetPosition: Position.Top,
    sourcePosition: Position.Bottom,
    style: nodeStyle(palette.amber),
  },
  {
    id: "south",
    position: { x: 470, y: 196 },
    data: { label: <GraphLabel title="SOUTH CELL" sub="p95 19ms | sync 0.99" accent={palette.green} /> },
    targetPosition: Position.Left,
    sourcePosition: Position.Left,
    style: nodeStyle(palette.green),
  },
  {
    id: "containment",
    position: { x: 250, y: 370 },
    data: { label: <GraphLabel title="CONTAINMENT BUS" sub="4 holds | 0 runaway" accent={palette.red} /> },
    targetPosition: Position.Top,
    style: nodeStyle(palette.red),
  },
];

const runtimeEdges: Edge[] = [
  edge("core", "north", "18ms / 97%"),
  edge("core", "harbor", "31ms / 88%", palette.amber),
  edge("core", "south", "19ms / 99%"),
  edge("north", "harbor", "12 req/s"),
  edge("south", "harbor", "9 req/s"),
  edge("harbor", "containment", "pressure 0.61", palette.red),
];

const eventStream = [
  ["15:12:40", "FEDERATION", "north-cell accepted quorum snapshot q-8841", "OK"],
  ["15:12:33", "EXECUTION", "harbor adaptive route degraded to safe lane", "WARN"],
  ["15:12:21", "COLLAPSE", "cascade guard retained water/energy dependency", "HOLD"],
  ["15:12:08", "KNOWLEDGE", "obsidian note linked to runtime incident inc-22a", "LINK"],
  ["15:11:58", "CONTROL", "policy delta propagated to 4 cells", "OK"],
  ["15:11:44", "TELEMATORY", "edge pressure sample normalized at 0.53", "OK"],
];

const runtimeRows = [
  ["control-plane", "90.4%", "0.18", "active"],
  ["telemetry-bus", "2.1k/s", "24ms", "nominal"],
  ["collapse-guard", "4 holds", "0 runaway", "armed"],
  ["federation-sync", "98.1%", "7 peers", "locked"],
];

export default function RuntimeConsole() {
  return (
    <main className="runtime-grid min-h-screen bg-[#070B12] p-3 text-[#D7E2F2] md:p-4">
      <div className="mx-auto flex max-w-[1800px] flex-col gap-3">
        <Header />

        <section className="grid min-h-[520px] grid-cols-1 gap-3 xl:grid-cols-[1fr_1.12fr]">
          <GraphPanel
            eyebrow="OBSIDIAN KNOWLEDGE GRAPH"
            title="Topology / Dependency / Runtime Federation"
            caption="Vault-derived control surface: dependencies, cascade paths, and federation semantics."
            nodes={knowledgeNodes}
            edges={knowledgeEdges}
          />
          <GraphPanel
            eyebrow="RUNTIME FEDERATION GRAPH"
            title="Operational Telemetry Only"
            caption="Live runtime cells, quorum health, latency edges, pressure routes, and containment state."
            nodes={runtimeNodes}
            edges={runtimeEdges}
            telemetry
          />
        </section>

        <ExecutionRow />
        <RuntimeRow />
        <TelematoryRow />
      </div>
    </main>
  );
}

function Header() {
  const stats = [
    ["MODE", "FEDERATED RUNTIME CONTROL", palette.cyan],
    ["COLLAPSE GUARD", "ARMED", palette.green],
    ["QUORUM", "90.4%", palette.green],
    ["INCIDENT PRESSURE", "0.61", palette.amber],
    ["CITY CELLS", "07 LINKED", palette.cyan],
  ];

  return (
    <header className="scanline relative overflow-hidden border border-[#1F2A3D] bg-[#101827]/92 p-3 shadow-[0_0_40px_rgba(0,0,0,0.35)]">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <div className="text-[10px] uppercase tracking-[0.38em] text-[#35D0FF]">
            Urban OS Runtime Federation
          </div>
          <h1 className="mt-1 text-xl font-semibold uppercase tracking-[0.16em] text-white md:text-3xl">
            Federated Runtime Control / Collapse Prevention Runtime
          </h1>
          <div className="mt-2 flex flex-wrap gap-2 text-[10px] uppercase tracking-[0.18em] text-[#6F7F99]">
            <span>Bloomberg-density console</span>
            <span className="text-[#1F2A3D]">|</span>
            <span>SOC runtime posture</span>
            <span className="text-[#1F2A3D]">|</span>
            <span>GitHub canonical build</span>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-2 md:grid-cols-5">
          {stats.map(([label, value, color]) => (
            <div key={label} className="border border-[#1F2A3D] bg-[#070B12]/80 px-3 py-2">
              <div className="text-[9px] uppercase tracking-[0.2em] text-[#6F7F99]">{label}</div>
              <div className="mt-1 text-[11px] font-semibold uppercase" style={{ color }}>
                {value}
              </div>
            </div>
          ))}
        </div>
      </div>
    </header>
  );
}

function GraphPanel({
  eyebrow,
  title,
  caption,
  nodes,
  edges,
  telemetry = false,
}: {
  eyebrow: string;
  title: string;
  caption: string;
  nodes: Node[];
  edges: Edge[];
  telemetry?: boolean;
}) {
  return (
    <Panel className="min-h-[520px]">
      <PanelHeading eyebrow={eyebrow} title={title} right={telemetry ? "EDGE LATENCY / QUORUM" : "TOPOLOGY MAP"} />
      <p className="mt-1 text-[10px] leading-5 text-[#6F7F99]">{caption}</p>
      <div className="mt-3 h-[430px] overflow-hidden border border-[#1F2A3D] bg-[#070B12]">
        <ReactFlow nodes={nodes} edges={edges} fitView minZoom={0.45} maxZoom={1.35} proOptions={{ hideAttribution: true }}>
          <Background color="#1F2A3D" gap={18} variant={BackgroundVariant.Lines} />
          <Controls showInteractive={false} position="bottom-right" />
          <MiniMap
            nodeColor={(node) => String(node.style?.borderColor ?? palette.cyan)}
            maskColor="rgba(7, 11, 18, 0.72)"
            pannable
            zoomable
          />
        </ReactFlow>
      </div>
    </Panel>
  );
}

function ExecutionRow() {
  return (
    <section className="grid grid-cols-1 gap-3 lg:grid-cols-2 2xl:grid-cols-4">
      <ExecutionCard
        label="EXECUTION CARD 01"
        title="Consensus Throughput"
        value="78 ops/s"
        tone={palette.cyan}
        footer="adaptive route execution"
      >
        <ResponsiveContainer width="100%" height={112}>
          <LineChart data={executionSeries}>
            <CartesianGrid stroke="#1F2A3D" strokeDasharray="2 4" />
            <XAxis dataKey="t" hide />
            <YAxis hide domain={[0, 90]} />
            <Tooltip content={<RuntimeTooltip />} />
            <Line type="monotone" dataKey="a" stroke={palette.cyan} strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="c" stroke={palette.green} strokeWidth={1.4} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </ExecutionCard>

      <ExecutionCard
        label="EXECUTION CARD 02"
        title="Collapse Pressure Bands"
        value="0.61"
        tone={palette.amber}
        footer="zone-local guardrails"
      >
        <ResponsiveContainer width="100%" height={112}>
          <BarChart data={collapseBands}>
            <XAxis dataKey="zone" tick={{ fill: palette.muted, fontSize: 9 }} axisLine={false} tickLine={false} />
            <YAxis hide domain={[0, 100]} />
            <Tooltip content={<RuntimeTooltip />} />
            <Bar dataKey="value" radius={[2, 2, 0, 0]}>
              {collapseBands.map((entry) => (
                <Cell key={entry.zone} fill={entry.value > 70 ? palette.red : entry.value > 55 ? palette.amber : palette.green} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </ExecutionCard>

      <ExecutionCard
        label="EXECUTION CARD 03"
        title="Containment Radius"
        value="82%"
        tone={palette.green}
        footer="runaway prevention envelope"
      >
        <ResponsiveContainer width="100%" height={112}>
          <RadialBarChart innerRadius="58%" outerRadius="96%" data={[{ name: "containment", value: 82, fill: palette.green }]} startAngle={210} endAngle={-30}>
            <RadialBar dataKey="value" cornerRadius={8} background={{ fill: "#1F2A3D" }} />
            <Tooltip content={<RuntimeTooltip />} />
          </RadialBarChart>
        </ResponsiveContainer>
      </ExecutionCard>

      <ExecutionCard
        label="EXECUTION CARD 04"
        title="Telemetry Flux"
        value="2.1k/s"
        tone={palette.violet}
        footer="runtime bus pressure"
      >
        <ResponsiveContainer width="100%" height={112}>
          <AreaChart data={telemetryFlux}>
            <defs>
              <linearGradient id="flux" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={palette.violet} stopOpacity={0.7} />
                <stop offset="95%" stopColor={palette.violet} stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <XAxis dataKey="t" hide />
            <YAxis hide domain={[0, 100]} />
            <Tooltip content={<RuntimeTooltip />} />
            <Area type="stepAfter" dataKey="pressure" stroke={palette.violet} fill="url(#flux)" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </ExecutionCard>
    </section>
  );
}

function RuntimeRow() {
  return (
    <section className="grid grid-cols-1 gap-3 xl:grid-cols-[0.9fr_1.1fr]">
      <Panel>
        <PanelHeading eyebrow="RUNTIME ROW" title="Federation Runtime State" right="CONTROL-PLANE" />
        <div className="mt-3 grid gap-2">
          {runtimeRows.map(([name, primary, secondary, state]) => (
            <div key={name} className="grid grid-cols-[1.1fr_0.7fr_0.7fr_0.7fr] items-center border border-[#1F2A3D] bg-[#070B12]/78 px-3 py-2 text-[11px] uppercase">
              <span className="text-[#D7E2F2]">{name}</span>
              <span className="text-[#35D0FF]">{primary}</span>
              <span className="text-[#6F7F99]">{secondary}</span>
              <span className="text-right text-[#5CFFB1]">{state}</span>
            </div>
          ))}
        </div>
      </Panel>
      <Panel>
        <PanelHeading eyebrow="RUNTIME ROW" title="Latency / Pressure / Quorum" right="7-CELL MESH" />
        <div className="mt-3 h-[186px]">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={telemetryFlux}>
              <CartesianGrid stroke="#1F2A3D" strokeDasharray="2 5" />
              <XAxis dataKey="t" tick={{ fill: palette.muted, fontSize: 9 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: palette.muted, fontSize: 9 }} axisLine={false} tickLine={false} />
              <Tooltip content={<RuntimeTooltip />} />
              <Line type="monotone" dataKey="latency" stroke={palette.cyan} strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="pressure" stroke={palette.amber} strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="quorum" stroke={palette.green} strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </Panel>
    </section>
  );
}

function TelematoryRow() {
  return (
    <Panel>
      <PanelHeading eyebrow="TELEMATORY ROW" title="Operational Event Stream" right="COMPACT TELEMETRY BUS" />
      <div className="mt-3 grid gap-1">
        {eventStream.map(([time, domain, message, state], index) => (
          <motion.div
            key={`${time}-${domain}`}
            initial={{ opacity: 0, x: -6 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: index * 0.04 }}
            className="grid grid-cols-[82px_112px_1fr_72px] items-center border border-[#1F2A3D] bg-[#070B12]/78 px-3 py-1.5 text-[10px] uppercase tracking-[0.04em]"
          >
            <span className="text-[#6F7F99]">{time}</span>
            <span className="text-[#35D0FF]">{domain}</span>
            <span className="truncate text-[#D7E2F2]">{message}</span>
            <span className={state === "WARN" ? "text-right text-[#FFCC66]" : state === "HOLD" ? "text-right text-[#FF5F7A]" : "text-right text-[#5CFFB1]"}>
              {state}
            </span>
          </motion.div>
        ))}
      </div>
    </Panel>
  );
}

function ExecutionCard({
  label,
  title,
  value,
  tone,
  footer,
  children,
}: {
  label: string;
  title: string;
  value: string;
  tone: string;
  footer: string;
  children: React.ReactNode;
}) {
  return (
    <Panel>
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-[9px] uppercase tracking-[0.24em] text-[#6F7F99]">{label}</div>
          <h3 className="mt-1 text-[12px] font-semibold uppercase tracking-[0.14em] text-white">{title}</h3>
        </div>
        <div className="text-right">
          <div className="text-lg font-semibold" style={{ color: tone }}>
            {value}
          </div>
          <div className="text-[9px] uppercase tracking-[0.16em] text-[#6F7F99]">{footer}</div>
        </div>
      </div>
      <div className="mt-3 border border-[#1F2A3D] bg-[#070B12]/80 p-2">{children}</div>
    </Panel>
  );
}

function Panel({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <motion.section
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35 }}
      className={`scanline relative overflow-hidden border border-[#1F2A3D] bg-[#101827]/94 p-3 shadow-[inset_0_1px_0_rgba(255,255,255,0.03),0_0_30px_rgba(0,0,0,0.22)] ${className}`}
    >
      {children}
    </motion.section>
  );
}

function PanelHeading({ eyebrow, title, right }: { eyebrow: string; title: string; right: string }) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-[#1F2A3D] pb-2">
      <div>
        <div className="text-[9px] uppercase tracking-[0.24em] text-[#35D0FF]">{eyebrow}</div>
        <h2 className="mt-1 text-sm font-semibold uppercase tracking-[0.14em] text-white">{title}</h2>
      </div>
      <div className="shrink-0 border border-[#1F2A3D] bg-[#070B12] px-2 py-1 text-[9px] uppercase tracking-[0.18em] text-[#6F7F99]">
        {right}
      </div>
    </div>
  );
}

function GraphLabel({ title, sub, accent }: { title: string; sub: string; accent: string }) {
  return (
    <div className="min-w-[138px]">
      <div className="text-[10px] font-semibold uppercase tracking-[0.12em]" style={{ color: accent }}>
        {title}
      </div>
      <div className="mt-1 text-[9px] uppercase tracking-[0.08em] text-[#8FA1BD]">{sub}</div>
    </div>
  );
}

function RuntimeTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ name: string; value: number }>; label?: string }) {
  if (!active || !payload?.length) {
    return null;
  }

  return (
    <div className="border border-[#1F2A3D] bg-[#070B12] px-2 py-1 text-[10px] uppercase text-[#D7E2F2] shadow-xl">
      {label ? <div className="mb-1 text-[#6F7F99]">{label}</div> : null}
      {payload.map((item) => (
        <div key={item.name} className="flex min-w-[120px] justify-between gap-4">
          <span>{item.name}</span>
          <span className="text-[#35D0FF]">{item.value}</span>
        </div>
      ))}
    </div>
  );
}

function nodeStyle(accent: string) {
  return {
    background: "#0A111D",
    border: `1px solid ${accent}`,
    borderRadius: 0,
    boxShadow: `0 0 18px ${accent}22`,
    color: "#D7E2F2",
    padding: 8,
  };
}

function edge(source: string, target: string, label: string, color = palette.cyan): Edge {
  return {
    id: `${source}-${target}`,
    source,
    target,
    label,
    animated: true,
    markerEnd: {
      type: MarkerType.ArrowClosed,
      color,
    },
    style: {
      stroke: color,
      strokeWidth: 1.4,
    },
    labelStyle: {
      fill: "#8FA1BD",
      fontSize: 9,
      letterSpacing: "0.08em",
      textTransform: "uppercase",
    },
    labelBgStyle: {
      fill: "#070B12",
      fillOpacity: 0.92,
    },
  };
}
