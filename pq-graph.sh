#!/usr/bin/env bash
set -euo pipefail

FILE="${1:-graph.json}"
PORT="${PORT:-8000}"

[[ -f "$FILE" ]] || {
  echo "Missing file: $FILE" >&2
  exit 1
}

TMPDIR="$(mktemp -d)"

cleanup() {
  kill "${SERVER_PID:-}" 2>/dev/null || true
  rm -rf "$TMPDIR"
}

trap cleanup EXIT INT TERM

cp "$FILE" "$TMPDIR/graph.json"

cat > "$TMPDIR/index.html" <<'EOF'
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>pq-map graph</title>

  <style>
    html, body, #graph {
      width: 100%;
      height: 100%;
      margin: 0;
      overflow: hidden;
      background: #050510;
    }

    #legend {
      position: absolute;
      left: 14px;
      top: 14px;
      z-index: 10;
      padding: 10px 13px;
      background: rgba(10,10,20,.75);
      color: #ddd;
      font: 12px sans-serif;
      line-height: 1.6;
      pointer-events: none;
      border: 1px solid rgba(255,255,255,.08);
      border-radius: 8px;
      backdrop-filter: blur(8px);
    }

    #controls {
      position: absolute;
      top: 14px;
      right: 14px;
      z-index: 20;
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 6px;
      background: rgba(10,10,20,.78);
      border: 1px solid rgba(255,255,255,.08);
      border-radius: 10px;
      backdrop-filter: blur(10px);
      box-shadow: 0 8px 28px rgba(0,0,0,.22);
      font: 12px sans-serif;
    }

    #controls button {
      appearance: none;
      border: 1px solid rgba(255,255,255,.10);
      background: rgba(255,255,255,.045);
      color: rgba(255,255,255,.82);
      padding: 7px 10px;
      border-radius: 7px;
      cursor: pointer;
      font: inherit;
      transition: background .12s ease, border-color .12s ease, color .12s ease;
    }

    #controls button:hover {
      background: rgba(255,255,255,.10);
      border-color: rgba(255,255,255,.18);
      color: #fff;
    }

    #controls button.active {
      background: rgba(124,167,255,.20);
      border-color: rgba(124,167,255,.55);
      color: #dbe7ff;
    }

    #controls button.primary {
      background: rgba(255,255,255,.10);
    }

    #selection {
      max-width: 290px;
      margin-right: 4px;
      padding: 0 7px;
      color: rgba(255,255,255,.60);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    #selection strong {
      color: rgba(255,255,255,.90);
      font-weight: 600;
    }

    #node-browser {
      position: absolute;
      right: 14px;
      top: 64px;
      z-index: 20;
      width: min(360px, calc(100vw - 28px));
      max-height: calc(100vh - 108px);
      display: flex;
      flex-direction: column;
      overflow: hidden;
      background: rgba(10,10,20,.82);
      border: 1px solid rgba(255,255,255,.08);
      border-radius: 10px;
      backdrop-filter: blur(10px);
      box-shadow: 0 8px 28px rgba(0,0,0,.22);
      color: rgba(255,255,255,.82);
      font: 12px sans-serif;
    }

    #node-browser-header {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 10px;
      padding: 10px 11px 7px;
    }

    #node-browser-title {
      color: rgba(255,255,255,.92);
      font-weight: 600;
      letter-spacing: .02em;
    }

    #node-browser-count {
      color: rgba(255,255,255,.46);
      white-space: nowrap;
    }

    #node-search-wrap {
      padding: 0 9px 8px;
    }

    #node-role-filters {
      display: flex;
      flex-wrap: wrap;
      gap: 5px;
      padding: 0 9px 9px;
    }

    .node-role-filter {
      appearance: none;
      border: 1px solid rgba(255,255,255,.09);
      border-radius: 999px;
      padding: 4px 7px;
      background: rgba(255,255,255,.035);
      color: rgba(255,255,255,.52);
      cursor: pointer;
      font: inherit;
      font-size: 10px;
      line-height: 1.1;
    }

    .node-role-filter:hover {
      background: rgba(255,255,255,.08);
      color: rgba(255,255,255,.85);
    }

    .node-role-filter.active {
      border-color: rgba(124,167,255,.55);
      background: rgba(124,167,255,.17);
      color: #dbe7ff;
    }

    #node-search {
      box-sizing: border-box;
      width: 100%;
      appearance: none;
      outline: none;
      border: 1px solid rgba(255,255,255,.11);
      border-radius: 7px;
      padding: 8px 9px;
      background: rgba(255,255,255,.045);
      color: rgba(255,255,255,.92);
      font: inherit;
    }

    #node-search:focus {
      border-color: rgba(124,167,255,.58);
      background: rgba(255,255,255,.07);
    }

    #node-search::placeholder {
      color: rgba(255,255,255,.32);
    }

    #node-list {
      overflow-y: auto;
      overscroll-behavior: contain;
      border-top: 1px solid rgba(255,255,255,.06);
    }

    .node-result {
      display: grid;
      grid-template-columns: 10px minmax(0, 1fr);
      gap: 8px;
      width: 100%;
      box-sizing: border-box;
      padding: 8px 10px;
      border: 0;
      border-bottom: 1px solid rgba(255,255,255,.045);
      background: transparent;
      color: rgba(255,255,255,.80);
      text-align: left;
      cursor: pointer;
      font: inherit;
    }

    .node-result:hover,
    .node-result.active {
      background: rgba(124,167,255,.11);
      color: #fff;
    }

    .node-result-dot {
      width: 7px;
      height: 7px;
      margin-top: 4px;
      border-radius: 50%;
      background: var(--node-color, #999);
      box-shadow: 0 0 7px color-mix(in srgb, var(--node-color, #999) 65%, transparent);
    }

    .node-result-main {
      min-width: 0;
    }

    .node-result-label {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .node-result-alias {
      margin-top: 2px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: rgba(255,255,255,.58);
    }

    .node-result-alias::before {
      content: "↳ ";
      color: rgba(255,255,255,.32);
    }

    .node-result-meta {
      margin-top: 2px;
      color: rgba(255,255,255,.38);
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: .05em;
    }

    #node-list-empty {
      padding: 14px 11px;
      color: rgba(255,255,255,.42);
    }
  </style>

  <script src="https://cdn.jsdelivr.net/npm/3d-force-graph"></script>
</head>

<body>

<div id="graph"></div>

<div id="legend">
  Interactive topology of observed cryptographic relationships.
</div>

<div id="node-browser">
  <div id="node-browser-header">
    <div id="node-browser-title">Nodes</div>
    <div id="node-browser-count"></div>
  </div>
  <div id="node-search-wrap">
    <input id="node-search" type="search" autocomplete="off" spellcheck="false"
           placeholder="Search nodes, e.g. host allegro">
  </div>
  <div id="node-role-filters"></div>
  <div id="node-list"></div>
</div>

<div id="controls">
  <div id="selection">Full graph</div>
  <button id="hop1" disabled title="Select a node first; then show its direct neighbours">1 hop</button>
  <button id="details" disabled title="Show the selected entity's semantic details without expanding through shared nodes">Details</button>
  <button id="hop2" disabled title="Select a node first; then show neighbours-of-neighbours">2 hops</button>
  <button id="back" class="primary" hidden title="Return to the full graph and restore the view from before drill-down">Back</button>
  <button id="resetView" title="Return to the full graph and restore the initial view">Reset view</button>
</div>

<script type="module">

import SpriteText from "https://esm.sh/three-spritetext";

import {
  forceX,
  forceY,
  forceZ
} from "https://esm.sh/d3-force-3d";


/* ---------------------------------------------------------
 * LOAD
 * --------------------------------------------------------- */

const response = await fetch("./graph.json");

if (!response.ok) {
  throw new Error(`graph.json: HTTP ${response.status}`);
}

const canonicalData = await response.json();

/* ---------------------------------------------------------
 * DISPLAY PROJECTION
 *
 * Keep HOST nodes lossless in the graph. Apex + www grouping is now a
 * browser-only presentation feature, so both underlying nodes must remain
 * available for selection and neighbourhood inspection.
 * --------------------------------------------------------- */

function rawEndpointId(endpoint) {
  return typeof endpoint === "object" ? endpoint.id : endpoint;
}

function relationName(link) {
  return link.label || link.type || "";
}

function buildDisplayProjection(canonical) {
  return {
    nodes: canonical.nodes.map(node => ({ ...node })),
    links: canonical.links.map(link => ({ ...link }))
  };
}

const data = buildDisplayProjection(canonicalData);

const nodeById = new Map(
  data.nodes.map(node => [node.id, node])
);

/* ---------------------------------------------------------
 * CA HIERARCHY
 *
 * Prefer an explicit metadata.ca_role from the producer, but infer it from
 * issued_by edges as a fallback so older graph JSON still renders correctly.
 * A CA that is itself issued by another CA is an intermediate. A CA with no
 * parent CA in the graph is treated as a root/trust anchor.
 * --------------------------------------------------------- */

function annotateCaRoles() {
  const caIds = new Set(
    data.nodes
      .filter(node => node.group === "issuer")
      .map(node => node.id)
  );

  const caWithParent = new Set();

  for (const link of data.links) {
    const relation = link.label || link.type || "";
    if (relation !== "issued_by") continue;

    const sourceId = rawEndpointId(link.source);
    const targetId = rawEndpointId(link.target);

    if (caIds.has(sourceId) && caIds.has(targetId)) {
      caWithParent.add(sourceId);
    }
  }

  for (const node of data.nodes) {
    if (!caIds.has(node.id)) continue;

    const explicit = node.metadata?.ca_role || node.meta?.ca_role;
    node._caRole = explicit || (caWithParent.has(node.id) ? "intermediate" : "root");
  }
}

annotateCaRoles();

/* Keep references to the complete graph. 3d-force-graph mutates
 * link endpoints into node objects, so all filtering code below
 * accepts either IDs or objects.
 */
const fullData = {
  nodes: data.nodes,
  links: data.links
};

const adjacency = new Map(
  fullData.nodes.map(node => [node.id, new Set()])
);

function endpointId(endpoint) {
  return typeof endpoint === "object" ? endpoint.id : endpoint;
}

for (const link of fullData.links) {
  const sourceId = endpointId(link.source);
  const targetId = endpointId(link.target);

  adjacency.get(sourceId)?.add(targetId);
  adjacency.get(targetId)?.add(sourceId);
}


/* ---------------------------------------------------------
 * ROLE
 * --------------------------------------------------------- */

function role(node) {

  if (node.type === "host") {
    return "host";
  }

  if (node.group === "certificate") {
    return "certificate";
  }

  if (node.group === "issuer") {
    return node._caRole === "root" ? "root_ca" : "intermediate_ca";
  }

  if (node.group === "certificate_key") {
    return "certificate_key";
  }

  if (node.group === "certificate_signature") {
    return "certificate_signature";
  }

  if (node.group === "key_exchange") {
    return "key_exchange";
  }

  if (node.group === "symmetric") {
    return "symmetric";
  }

  if (
    node.type === "service" ||
    node.group === "tcp_service"
  ) {
    return "service";
  }

  return "other";
}

function relationForPerspective(relation, outgoing) {
  if (outgoing) {
    return displayRelation(relation);
  }

  switch (relation) {
    case "issued_by":
      return "issues";

    case "presents_certificate":
      return "presented by";

    case "certificate_for":
      return "certificate used by";

    case "negotiated_kx":
      return "negotiated by";

    case "symmetric_cipher":
      return "used by";

    case "exposes":
      return "exposed by";

    case "cert_key":
      return "key of";

    case "cert_signature":
      return "signature of";

    default:
      return displayRelation(relation);
  }
}

function displayRelation(relation) {
  switch (relation) {
    case "presents_certificate":
      return "presents certificate";

    case "certificate_for":
      return "certificate used by";

    case "negotiated_kx":
      return "negotiated by";

    case "symmetric_cipher":
      return "symmetric cipher";

    case "issued_by":
      return "issues";

    case "cert_key":
      return "certificate key";

    case "cert_signature":
      return "certificate signature";

    case "exposes":
      return "exposes";

    default:
      return relation;
  }
}

function displayLabel(node) {

  switch (role(node)) {

    case "host":
      return `HOST · ${node.label}`;

    case "certificate":
      return `CERT · ${node.label}`;

    case "root_ca":
      return `ROOT CA · ${node.label}`;

    case "intermediate_ca":
      return `CA · ${node.label}`;

    default:
      return node.label || node.id;
  }
}


/* ---------------------------------------------------------
 * SEMANTIC POSITION
 * --------------------------------------------------------- */

function targetX(node) {

  switch (role(node)) {

    case "root_ca":
      return -350;

    case "intermediate_ca":
      return -230;

    case "certificate_key":
    case "certificate_signature":
      return -230;

    case "certificate":
      return -110;

    case "host":
      return 0;

    case "key_exchange":
    case "symmetric":
    case "service":
      return 150;

    default:
      return 0;
  }
}


function targetZ(node) {

  switch (role(node)) {

    case "root_ca":
      return 110;

    case "intermediate_ca":
      return 75;

    case "certificate_key":
      return 0;

    case "certificate_signature":
      return -90;

    case "certificate":
      return 0;

    case "host":
      return 0;

    case "key_exchange":
      return 75;

    case "symmetric":
      return -25;

    case "service":
      return -125;

    default:
      return 0;
  }
}


/* ---------------------------------------------------------
 * INITIAL POSITIONS
 * --------------------------------------------------------- */

const roleCounters = {};

for (const node of data.nodes) {

  const r = role(node);

  const i = roleCounters[r] || 0;
  roleCounters[r] = i + 1;

  const level =
    i === 0
      ? 0
      : Math.ceil(i / 2) * (i % 2 ? 1 : -1);

  let spacing = 24;

  if (r === "host") {
    spacing = 5;
  }

  if (r === "certificate") {
    spacing = 6;
  }

  node.x = targetX(node);
  node.y = level * spacing;
  node.z = targetZ(node);

  if (r === "host") {
    node.z += ((i % 7) - 3) * 7;
  }

  if (r === "certificate") {
    node.z += ((i % 5) - 2) * 8;
  }
}


/* ---------------------------------------------------------
 * NEIGHBOURS
 * --------------------------------------------------------- */

for (const node of data.nodes) {
  node.links = [];
}

for (const link of data.links) {

  const source =
    typeof link.source === "object"
      ? link.source
      : nodeById.get(link.source);

  const target =
    typeof link.target === "object"
      ? link.target
      : nodeById.get(link.target);

  if (!source || !target) {
    continue;
  }

  source.links.push(link);
  target.links.push(link);
}


/* ---------------------------------------------------------
 * HIGHLIGHT STATE
 *
 * Only links are dynamically redrawn.
 * --------------------------------------------------------- */

const highlightLinks = new Set();

// Persistent investigation selection.
let selectedNodeId = null;
let selectedNodeIds = new Set();
let hopDepth = 1;
let investigationMode = "hop1";

function isInvestigating() {
  return selectedNodeIds.size > 0;
}

function isSelectedNode(node) {
  return selectedNodeIds.has(node.id);
}

// Search is orthogonal to investigation: it narrows the browser list and
// highlights matching nodes without changing graph topology.
let nodeSearchQuery = "";
let selectedNodeRole = "all";
let searchMatchIds = new Set();


/* ---------------------------------------------------------
 * COLORS
 * --------------------------------------------------------- */

function baseColor(node) {

  switch (role(node)) {

    case "host":
      return "#7ca7ff";

    case "certificate":
      return "#c9c9d2";

    case "root_ca":
      return "#ff8c42";

    case "intermediate_ca":
      return "#ffb65c";

    case "certificate_key":
      return "#dca6ff";

    case "certificate_signature":
      return "#ff8fa3";

    case "key_exchange":
      return "#67e8c2";

    case "symmetric":
      return "#70c9ff";

    case "service":
      return "#ffd866";

    default:
      return "#999999";
  }
}


function hasActiveSearch() {
  return nodeSearchQuery.trim().length > 0 || selectedNodeRole !== "all";
}

function isSearchMatch(node) {
  return searchMatchIds.has(node.id);
}

function nodeColor(node) {
  if (isSelectedNode(node)) return "#ffffff";

  // Investigation mode takes visual precedence over browser/search filtering.
  // Once a node is opened in 1-hop/2-hop view, its neighbours must remain
  // readable even when the browser is still filtered to e.g. "service".
  if (isInvestigating()) return baseColor(node);

  if (hasActiveSearch()) {
    return isSearchMatch(node)
      ? "#ffffff"
      : "#343440";
  }

  return baseColor(node);
}


/* ---------------------------------------------------------
 * SIZE
 * --------------------------------------------------------- */

function nodeSize(node) {

  let size;

  switch (role(node)) {
    case "host": size = 1.2; break;
    case "certificate": size = 1.1; break;
    case "root_ca": size = 6.5; break;
    case "intermediate_ca": size = 5; break;
    case "certificate_key":
    case "certificate_signature": size = 3; break;
    case "key_exchange": size = 5; break;
    case "symmetric":
    case "service": size = 4; break;
    default: size = 2;
  }

  if (isSelectedNode(node)) {
    return Math.max(size * 4, 8);
  }

  if (!isInvestigating() && hasActiveSearch() && isSearchMatch(node)) {
    return Math.max(size * 2.2, 4);
  }

  return size;
}



/* ---------------------------------------------------------
 * TEXT
 *
 * IMPORTANT:
 * generated once.
 * Never regenerated during hover.
 * --------------------------------------------------------- */

function textHeight(node) {

  switch (role(node)) {

    case "host":
      return 2.0;

    case "certificate":
      return 1.8;

    case "root_ca":
      return 5.2;

    case "intermediate_ca":
      return 4.5;

    case "certificate_key":
    case "certificate_signature":
      return 3.5;

    case "key_exchange":
      return 4.5;

    case "symmetric":
    case "service":
      return 4;

    default:
      return 2.5;
  }
}


function makeText(node) {

  const selected = isSelectedNode(node);
  const text = selected
    ? `● SELECTED\n${displayLabel(node)}`
    : displayLabel(node);

  const sprite = new SpriteText(text);
  sprite.material.depthWrite = false;

  if (selected) {
    sprite.color = "#ffffff";
    sprite.textHeight = 6;
    sprite.center.y = -1.35;
  } else if (!isInvestigating() && hasActiveSearch()) {
    // Search/filter dimming applies only while browsing the full graph.
    // In investigation mode every visible neighbour gets its normal label.
    sprite.color = isSearchMatch(node) ? "#ffffff" : "#343440";
    sprite.textHeight = isSearchMatch(node)
      ? Math.max(textHeight(node) * 1.35, 2.8)
      : textHeight(node);
    sprite.center.y = -0.65;
  } else {
    sprite.color = baseColor(node);
    sprite.textHeight = textHeight(node);
    sprite.center.y = -0.65;
  }

  return sprite;
}



/* ---------------------------------------------------------
 * GRAPH
 * --------------------------------------------------------- */

const Graph =
  new ForceGraph3D(
    document.getElementById("graph")
  )

  .graphData(data)

  .nodeVal(nodeSize)

  .nodeColor(nodeColor)

  /*
   * Sphere + permanent SpriteText.
   */
  .nodeThreeObject(makeText)

  .nodeThreeObjectExtend(true)

  .nodeLabel(node => {

  const connections = [];

  const visibleNodeIds = new Set(
    Graph.graphData().nodes.map(n => n.id)
  );

  for (const link of node.links) {

    const source =
      typeof link.source === "object"
        ? link.source
        : nodeById.get(link.source);

    const target =
      typeof link.target === "object"
        ? link.target
        : nodeById.get(link.target);

    if (!source || !target) continue;
    if (!visibleNodeIds.has(source.id) || !visibleNodeIds.has(target.id)) continue;

    const relation =
      link.label || link.type || "";

    if (source === node) {
      connections.push({
        direction: "→",
        outgoing: true,
        node: target,
        relation
      });
    } else {
      connections.push({
        direction: "←",
        outgoing: false,
        node: source,
        relation
      });
    }
  }

  connections.sort((a, b) =>
    displayLabel(a.node)
      .localeCompare(displayLabel(b.node))
  );

  if (role(node) === "host" && node.compactedHost && node.aliases?.length) {
    const lines = [
      `<b>HOST · ${node.label}</b>`,
      "",
      `<span style="opacity:.65">[aliases]</span>`
    ];

    for (const alias of node.aliases) {
      const certText = alias.certificates?.length
        ? alias.certificates.join(", ")
        : "none observed";

      lines.push(
        `${alias.label} <span style="opacity:.72">(cert: ${certText})</span>`
      );
    }

    lines.push("");

    const preferredRelations = [
      "exposes",
      "negotiated_kx",
      "symmetric_cipher"
    ];

    for (const relation of preferredRelations) {
      const matching = connections.filter(c => c.relation === relation);
      const seen = new Set();

      for (const c of matching) {
        const value = c.node.label || c.node.id;
        if (seen.has(value)) continue;
        seen.add(value);

        lines.push(
          `<span style="opacity:.65">[${relationForPerspective(c.relation, c.outgoing)}]</span> ` +
          `${value}`
        );
      }
    }

    return lines.join("<br>");
  }

  // Certificate tooltips are entity summaries, not raw graph-edge dumps.
  if (role(node) === "certificate") {
    const metadata = node.metadata || node.meta || {};
    const sans = Array.isArray(metadata.sans)
      ? [...new Set(metadata.sans.filter(Boolean))]
      : [];
    const certLabel = (node.label || node.id)
      .replace(/\s+\+\d+\s+SANs?$/i, "");

    const lines = [
      `<b>CERT · ${certLabel}</b>`,
      ""
    ];

    const hosts = [];
    const issuers = [];
    const keys = [];
    const signatures = [];
    const other = [];

    for (const c of connections) {
      switch (c.relation) {
        case "presents_certificate":
        case "certificate_for":
          hosts.push(c.node.label || c.node.id);
          break;

        case "issued_by":
          issuers.push(c.node.label || c.node.id);
          break;

        case "cert_key":
          keys.push(c.node.label || c.node.id);
          break;

        case "cert_signature":
          signatures.push(c.node.label || c.node.id);
          break;

        default:
          other.push(c);
      }
    }

    const unique = values => [...new Set(values.filter(Boolean))];
    const hostNames = unique(hosts);
    const issuerNames = unique(issuers);
    const keyNames = unique(keys);
    const signatureNames = unique(signatures);

    // Human-facing summary first. Keep X.509 terminology out of the main
    // reading path: "Used by" is observed deployment; "Covers" is the set of
    // DNS names carried by the certificate metadata.
    lines.push(
      `<span style="opacity:.60">Used by</span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; ` +
      `${hostNames.length} observed host${hostNames.length === 1 ? "" : "s"}`
    );

    lines.push(
      `<span style="opacity:.60">Covers</span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; ` +
      `${sans.length} hostname${sans.length === 1 ? "" : "s"}`
    );

    lines.push("");

    if (issuerNames[0]) {
      lines.push(`<span style="opacity:.60">Issuer</span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; ${issuerNames[0]}`);
    }

    if (keyNames[0]) {
      lines.push(`<span style="opacity:.60">Key</span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; ${keyNames[0]}`);
    }

    if (signatureNames[0]) {
      lines.push(`<span style="opacity:.60">Signature</span>&nbsp; ${signatureNames[0]}`);
    }

    if (metadata.not_before || metadata.not_after) {
      const formatDate = value => value ? String(value).slice(0, 10) : "?";
      lines.push(
        `<span style="opacity:.60">Valid</span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; ` +
        `${formatDate(metadata.not_before)} → ${formatDate(metadata.not_after)}`
      );
    }

    // Preserve unexpected relations rather than silently dropping them.
    if (other.length) {
      lines.push("");
      for (const c of other) {
        lines.push(
          `<span style="opacity:.55">${relationForPerspective(c.relation, c.outgoing)}</span> ` +
          `${displayLabel(c.node)}`
        );
      }
    }

    // Full evidence once, at the bottom. This keeps the top compact while the
    // user can still inspect every observed presenter and every covered name.
    if (hostNames.length || sans.length) {
      lines.push("");
      lines.push(`<span style="opacity:.30">────────────────────────</span>`);
    }

    if (hostNames.length) {
      lines.push("");
      lines.push(
        `<span style="opacity:.58;font-weight:600">Hosts using this certificate (${hostNames.length})</span>`
      );
      for (const host of hostNames) {
        lines.push(`<span style="opacity:.78">&nbsp;&nbsp;${host}</span>`);
      }
    }

    if (sans.length) {
      lines.push("");
      lines.push(
        `<span style="opacity:.58;font-weight:600">Hostnames covered by certificate (${sans.length})</span>`
      );
      for (const san of sans) {
        lines.push(`<span style="opacity:.78">&nbsp;&nbsp;${san}</span>`);
      }
    }

    return lines.join("<br>");
  }

  const lines = [
    `<b>${displayLabel(node)}</b>`,
    ""
  ];

  for (const c of connections) {
    lines.push(
      `<span style="opacity:.65">[${relationForPerspective(c.relation, c.outgoing)}]</span> ` +
      `${displayLabel(c.node)}`
    );
  }

  return lines.join("<br>");
})

  .linkLabel(link =>
    link.label || link.type || ""
  )

  /*
   * Cheap normal links.
   */
  .linkOpacity(link => {
    if (highlightLinks.has(link)) return 0.45;

    if (isInvestigating()) {
      const sourceId = endpointId(link.source);
      const targetId = endpointId(link.target);
      const direct = selectedNodeIds.has(sourceId) || selectedNodeIds.has(targetId);

      // In investigation mode make the selected node's direct relationships
      // clearly readable; keep 2-hop/internal context visible as well.
      return direct ? 0.32 : 0.12;
    }

    return 0.05;
  })

  .linkWidth(link => {
    if (highlightLinks.has(link)) return 0.65;

    if (isInvestigating()) {
      const sourceId = endpointId(link.source);
      const targetId = endpointId(link.target);
      const direct = selectedNodeIds.has(sourceId) || selectedNodeIds.has(targetId);

      return direct ? 0.50 : 0.22;
    }

    return 0.09;
  })

  /*
   * No particles.
   */
  .linkDirectionalParticles(0)

  .d3AlphaDecay(0.025)

  .d3VelocityDecay(0.35);


/* ---------------------------------------------------------
 * SEMANTIC FORCES
 * --------------------------------------------------------- */

Graph.d3Force(
  "semantic-x",
  forceX(node => targetX(node))
    .strength(node => {

      switch (role(node)) {

        case "host":
        case "certificate":
          return 0.22;

        default:
          return 0.55;
      }
    })
);


Graph.d3Force(
  "semantic-z",
  forceZ(node => targetZ(node))
    .strength(node => {

      switch (role(node)) {

        case "host":
        case "certificate":
          return 0.18;

        default:
          return 0.50;
      }
    })
);


Graph.d3Force(
  "semantic-y",
  forceY(0)
    .strength(0.015)
);


Graph
  .d3Force("charge")
  .strength(node => {

    switch (role(node)) {

      case "host":
        return -50;

      case "certificate":
        return -55;

      default:
        return -110;
    }
  });


Graph
  .d3Force("link")
  .distance(link => {

    const label =
      link.label || link.type || "";

    switch (label) {

      case "presents_certificate":
      case "certificate_for":
        return 38;

      case "issued_by":
        return 60;

      case "cert_key":
      case "cert_signature":
        return 55;

      case "negotiated_kx":
      case "symmetric_cipher":
        return 65;

      case "exposes":
        return 75;

      default:
        return 55;
    }
  });


/* ---------------------------------------------------------
 * FAST HIGHLIGHT
 *
 * Only link width accessor is refreshed.
 * No node rebuild.
 * No text rebuild.
 * No node recoloring.
 * No particles.
 * --------------------------------------------------------- */

function refreshHighlight() {
  Graph
    .linkWidth(Graph.linkWidth())
    .linkOpacity(Graph.linkOpacity());
}

function refreshSelection() {
  Graph
    .nodeVal(Graph.nodeVal())
    .nodeColor(Graph.nodeColor())
    .nodeThreeObject(Graph.nodeThreeObject())
    .linkWidth(Graph.linkWidth())
    .linkOpacity(Graph.linkOpacity());
}


Graph.onNodeHover(node => {

  highlightLinks.clear();

  if (node) {
    for (const link of node.links) {
      highlightLinks.add(link);
    }
  }

  refreshHighlight();
});


Graph.onLinkHover(link => {

  highlightLinks.clear();

  if (link) {
    highlightLinks.add(link);
  }

  refreshHighlight();
});


/* ---------------------------------------------------------
 * INVESTIGATION MODE
 *
 * Click a node to isolate its 1-hop neighbourhood. Details adds semantic
 * entity information without traversing through shared nodes; 2 hops stays
 * as the generic topological neighbourhood expansion.
 * Back restores the full graph and the camera position from before drill-down.
 * Reset view restores the full graph and the initial/default camera.
 * --------------------------------------------------------- */

let browsingCamera = null;
let initialCamera = null;

const hop1Button = document.getElementById("hop1");
const detailsButton = document.getElementById("details");
const hop2Button = document.getElementById("hop2");
const backButton = document.getElementById("back");
const resetViewButton = document.getElementById("resetView");
const selectionLabel = document.getElementById("selection");
const nodeSearchInput = document.getElementById("node-search");
const nodeList = document.getElementById("node-list");
const nodeBrowserCount = document.getElementById("node-browser-count");
const nodeRoleFilters = document.getElementById("node-role-filters");

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function globToRegExp(glob) {
  const source = glob
    .split("*")
    .map(escapeRegExp)
    .join(".*");

  return new RegExp(source, "i");
}

const CRYPTO_ROLES = new Set([
  "certificate_key",
  "certificate_signature",
  "key_exchange",
  "symmetric"
]);

function searchableNodeText(node) {
  const aliases = node.aliases
    ? node.aliases.flatMap(alias => [
        alias.id || "",
        alias.label || "",
        ...(alias.certificates || [])
      ])
    : [];

  const r = role(node);
  const categories = CRYPTO_ROLES.has(r) ? ["crypto"] : [];

  return [
    displayLabel(node),
    r,
    ...categories,
    node.type || "",
    node.group || "",
    node.id || "",
    node.label || "",
    ...aliases
  ].join("\n");
}

function queryTokens(rawQuery) {
  return rawQuery
    .trim()
    .split(/\s+/)
    .filter(Boolean);
}

function nodeMatchesQuery(node, rawQuery) {
  const tokens = queryTokens(rawQuery);
  if (!tokens.length) return true;

  const haystack = searchableNodeText(node);

  // Search terms are ANDed. Each term is a substring unless it contains '*'.
  // Example: "host allegro" => node must match both "host" and "allegro".
  return tokens.every(token => {
    const pattern = token.includes("*") ? token : `*${token}*`;
    return globToRegExp(pattern).test(haystack);
  });
}

function nodeMatchesRole(node) {
  if (selectedNodeRole === "all") return true;

  const r = role(node);
  if (selectedNodeRole === "crypto") return CRYPTO_ROLES.has(r);
  if (selectedNodeRole === "ca") return r === "intermediate_ca" || r === "root_ca";

  return r === selectedNodeRole;
}

function availableNodeRoles() {
  const present = new Set(fullData.nodes.map(node => role(node)));
  const filters = [];

  if (present.has("host")) filters.push("host");
  if (present.has("certificate")) filters.push("certificate");
  if (present.has("intermediate_ca") || present.has("root_ca")) filters.push("ca");
  if ([...CRYPTO_ROLES].some(r => present.has(r))) filters.push("crypto");
  if (present.has("service")) filters.push("service");
  if (present.has("other")) filters.push("other");

  return filters;
}

function renderRoleFilters() {
  nodeRoleFilters.replaceChildren();

  for (const r of ["all", ...availableNodeRoles()]) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "node-role-filter";
    button.classList.toggle("active", selectedNodeRole === r);
    button.textContent = ({
      ca: "CA"
    })[r] || r;

    button.addEventListener("click", event => {
      event.stopPropagation();
      selectedNodeRole = r;
      renderRoleFilters();
      renderNodeBrowser();
    });

    nodeRoleFilters.appendChild(button);
  }
}

/* Pick the scanned/base host for browser ordering. We do not need a
 * public-suffix parser here: the graph is a domain-scoped inventory, so the
 * base host is the non-www HOST that is the suffix of the largest number of
 * other HOST names. Ties prefer the shorter hostname.
 */
function browserBaseHostId() {
  const hosts = fullData.nodes.filter(node =>
    role(node) === "host" && node.label && !node.label.startsWith("www.")
  );

  let best = null;
  let bestDescendants = -1;

  for (const candidate of hosts) {
    const suffix = `.${candidate.label}`;
    const descendants = fullData.nodes.reduce((count, node) => {
      if (role(node) !== "host" || !node.label) return count;
      return count + (node.label.endsWith(suffix) ? 1 : 0);
    }, 0);

    if (
      descendants > bestDescendants ||
      (descendants === bestDescendants && best && candidate.label.length < best.label.length)
    ) {
      best = candidate;
      bestDescendants = descendants;
    }
  }

  return best?.id || null;
}

const baseHostId = browserBaseHostId();

function sortedNodes(nodes) {
  return [...nodes].sort((a, b) => {
    const roleOrder = role(a).localeCompare(role(b));
    if (roleOrder) return roleOrder;

    // Within HOST results, keep the scanned/base domain first. Its www
    // counterpart is rendered beneath it by browserRows().
    if (role(a) === "host") {
      if (a.id === baseHostId && b.id !== baseHostId) return -1;
      if (b.id === baseHostId && a.id !== baseHostId) return 1;
    }

    return displayLabel(a).localeCompare(displayLabel(b));
  });
}

/* Browser-only presentation grouping. Keep the graph model untouched:
 * when both foo.example and www.foo.example are present in the current
 * result set, render them as one HOST row.
 */
function browserRows(nodes) {
  const byHostLabel = new Map(
    nodes
      .filter(node => role(node) === "host" && !node.compactedHost)
      .map(node => [node.label, node])
  );

  const consumed = new Set();
  const rows = [];

  for (const node of nodes) {
    if (consumed.has(node.id)) continue;

    if (role(node) === "host" && !node.compactedHost && node.label && !node.label.startsWith("www.")) {
      const www = byHostLabel.get(`www.${node.label}`);

      if (www && !consumed.has(www.id)) {
        consumed.add(node.id);
        consumed.add(www.id);
        rows.push({
          primary: node,
          secondary: www
        });
        continue;
      }
    }

    // If the www node sorts before its apex for any reason, defer it until
    // the apex is processed so the pair still renders apex-first.
    if (role(node) === "host" && !node.compactedHost && node.label?.startsWith("www.")) {
      const apex = byHostLabel.get(node.label.slice(4));
      if (apex && !consumed.has(apex.id)) continue;
    }

    consumed.add(node.id);
    rows.push({ primary: node, secondary: null });
  }

  return rows;
}

function renderNodeBrowser() {
  const matches = sortedNodes(
    fullData.nodes.filter(node =>
      nodeMatchesRole(node) && nodeMatchesQuery(node, nodeSearchQuery)
    )
  );

  searchMatchIds = new Set(matches.map(node => node.id));

  nodeBrowserCount.textContent = hasActiveSearch()
    ? `${matches.length} / ${fullData.nodes.length}`
    : `${fullData.nodes.length}`;

  nodeList.replaceChildren();

  if (!matches.length) {
    const empty = document.createElement("div");
    empty.id = "node-list-empty";
    empty.textContent = "No matching nodes";
    nodeList.appendChild(empty);
  } else {
    const fragment = document.createDocumentFragment();

    for (const row of browserRows(matches)) {
      const node = row.primary;
      const secondary = row.secondary;

      const button = document.createElement("button");
      button.type = "button";
      button.className = "node-result";
      const rowNodeIds = secondary
        ? [node.id, secondary.id]
        : [node.id];

      button.classList.toggle(
        "active",
        rowNodeIds.some(id => selectedNodeIds.has(id))
      );
      button.title = secondary
        ? `${displayLabel(node)}\n${displayLabel(secondary)}`
        : displayLabel(node);
      button.dataset.nodeIds = JSON.stringify(rowNodeIds);

      const dot = document.createElement("span");
      dot.className = "node-result-dot";
      dot.style.setProperty("--node-color", baseColor(node));

      const main = document.createElement("span");
      main.className = "node-result-main";

      const label = document.createElement("div");
      label.className = "node-result-label";
      label.textContent = node.label || node.id;

      main.appendChild(label);

      if (secondary) {
        const alias = document.createElement("div");
        alias.className = "node-result-alias";
        alias.textContent = secondary.label || secondary.id;
        alias.title = displayLabel(secondary);
        main.appendChild(alias);
      }

      const meta = document.createElement("div");
      meta.className = "node-result-meta";
      meta.textContent = ({
        intermediate_ca: "intermediate CA",
        root_ca: "root CA"
      })[role(node)] || role(node);

      main.appendChild(meta);
      button.append(dot, main);

      // A grouped apex + www row is one browser entity. Clicking anywhere on
      // it selects both underlying graph nodes; ordinary rows still select one.
      button.addEventListener("click", event => {
        event.stopPropagation();

        if (!isInvestigating()) {
          saveBrowsingCamera();
        }

        hopDepth = 1;
        investigationMode = "hop1";
        showNeighborhood(rowNodeIds);
      });

      fragment.appendChild(button);
    }

    nodeList.appendChild(fragment);
  }

  refreshSelection();
}

function updateNodeSearch() {
  nodeSearchQuery = nodeSearchInput.value;
  renderNodeBrowser();
}

nodeSearchInput.addEventListener("input", updateNodeSearch);
nodeSearchInput.addEventListener("keydown", event => {
  // Keep typing/search shortcuts from leaking into graph-level key handling.
  event.stopPropagation();

  if (event.key === "Escape" && nodeSearchInput.value) {
    nodeSearchInput.value = "";
    updateNodeSearch();
  }
});

renderRoleFilters();

function captureCamera() {
  const camera = Graph.camera();
  const controls = Graph.controls();

  return {
    position: {
      x: camera.position.x,
      y: camera.position.y,
      z: camera.position.z
    },
    target: {
      x: controls.target.x,
      y: controls.target.y,
      z: controls.target.z
    }
  };
}

function saveBrowsingCamera() {
  browsingCamera = captureCamera();
}

function restoreCamera(saved, duration = 700) {
  if (!saved) return;

  requestAnimationFrame(() => {
    Graph.cameraPosition(
      saved.position,
      saved.target,
      duration
    );
  });
}

function collectNeighborhood(startIds, depth) {
  const seeds = Array.isArray(startIds) ? startIds : [startIds];
  const visited = new Set(seeds);
  let frontier = new Set(seeds);

  for (let level = 0; level < depth; level++) {
    const next = new Set();

    for (const id of frontier) {
      for (const neighborId of adjacency.get(id) || []) {
        if (!visited.has(neighborId)) {
          visited.add(neighborId);
          next.add(neighborId);
        }
      }
    }

    frontier = next;

    if (!frontier.size) {
      break;
    }
  }

  return visited;
}

function visibleGraphFor(startIds, depth) {
  const visibleIds = collectNeighborhood(startIds, depth);

  const nodes = fullData.nodes.filter(node =>
    visibleIds.has(node.id)
  );

  const links = fullData.links.filter(link => {
    const sourceId = endpointId(link.source);
    const targetId = endpointId(link.target);

    return visibleIds.has(sourceId) && visibleIds.has(targetId);
  });

  return { nodes, links };
}

function visibleDetailsFor(startIds) {
  const seeds = Array.isArray(startIds) ? startIds : [startIds];
  const visibleIds = new Set(seeds);

  const hostRelations = new Set([
    "exposes",
    "negotiated_kx",
    "symmetric_cipher",
    "presents_certificate",
    "certificate_for"
  ]);

  const certificateRelations = new Set([
    "issued_by",
    "cert_key",
    "cert_signature"
  ]);

  const certificateIds = new Set();

  function addOtherEndpoint(link, currentId) {
    const sourceId = endpointId(link.source);
    const targetId = endpointId(link.target);
    const otherId = sourceId === currentId ? targetId : sourceId;
    if (otherId) visibleIds.add(otherId);
    return otherId;
  }

  for (const seedId of seeds) {
    const seed = nodeById.get(seedId);
    if (!seed) continue;

    // Details is semantic for hosts. For other entity types, keep the
    // behaviour useful and conservative by showing their direct neighbours.
    if (role(seed) !== "host") {
      for (const link of seed.links || []) {
        addOtherEndpoint(link, seedId);
      }
      continue;
    }

    for (const link of seed.links || []) {
      const relation = relationName(link);
      if (!hostRelations.has(relation)) continue;

      const otherId = addOtherEndpoint(link, seedId);
      const other = nodeById.get(otherId);
      if (other && role(other) === "certificate") {
        certificateIds.add(otherId);
      }
    }
  }

  // Expand certificate descriptive metadata and follow issued_by recursively
  // through CA nodes so Details shows the complete path to the root. Do not
  // traverse through shared service/KX/cipher/key/signature nodes.
  const caQueue = [];
  const seenCas = new Set();

  for (const certificateId of certificateIds) {
    const certificate = nodeById.get(certificateId);
    if (!certificate) continue;

    for (const link of certificate.links || []) {
      const relation = relationName(link);
      if (!certificateRelations.has(relation)) continue;

      const otherId = addOtherEndpoint(link, certificateId);
      const other = nodeById.get(otherId);
      if (relation === "issued_by" && other &&
          (role(other) === "intermediate_ca" || role(other) === "root_ca")) {
        caQueue.push(otherId);
      }
    }
  }

  while (caQueue.length) {
    const caId = caQueue.shift();
    if (seenCas.has(caId)) continue;
    seenCas.add(caId);

    const ca = nodeById.get(caId);
    if (!ca) continue;

    for (const link of ca.links || []) {
      if (relationName(link) !== "issued_by") continue;

      const sourceId = endpointId(link.source);
      const targetId = endpointId(link.target);

      // issued_by is directed child -> parent; only walk upward.
      if (sourceId !== caId) continue;

      visibleIds.add(targetId);
      const parent = nodeById.get(targetId);
      if (parent &&
          (role(parent) === "intermediate_ca" || role(parent) === "root_ca")) {
        caQueue.push(targetId);
      }
    }
  }

  const nodes = fullData.nodes.filter(node => visibleIds.has(node.id));
  const links = fullData.links.filter(link => {
    const sourceId = endpointId(link.source);
    const targetId = endpointId(link.target);
    return visibleIds.has(sourceId) && visibleIds.has(targetId);
  });

  return { nodes, links };
}

function updateControls() {
  const investigating = isInvestigating();

  for (const row of nodeList.querySelectorAll(".node-result")) {
    let ids = [];
    try { ids = JSON.parse(row.dataset.nodeIds || "[]"); } catch {}
    row.classList.toggle("active", ids.some(id => selectedNodeIds.has(id)));
  }

  hop1Button.disabled = !investigating;
  detailsButton.disabled = !investigating;
  hop2Button.disabled = !investigating;
  backButton.hidden = !investigating;

  // A hop button is active only when a node is actually isolated.
  // This avoids the misleading initial state "1 hop" + full graph.
  hop1Button.classList.toggle("active", investigating && investigationMode === "hop1");
  detailsButton.classList.toggle("active", investigating && investigationMode === "details");
  hop2Button.classList.toggle("active", investigating && investigationMode === "hop2");

  if (!investigating) {
    selectionLabel.textContent = "Full graph";
    return;
  }

  const selectedNodes = [...selectedNodeIds]
    .map(id => nodeById.get(id))
    .filter(Boolean);

  selectionLabel.innerHTML = selectedNodes.length
    ? selectedNodes.map(node => `<strong>${displayLabel(node)}</strong>`).join(" + ")
    : "Selection";
}

function fitCurrentGraph(duration = 500, padding = 55) {
  requestAnimationFrame(() => {
    Graph.d3ReheatSimulation();

    setTimeout(() => {
      Graph.zoomToFit(duration, padding);
    }, 120);
  });
}

function showNeighborhood(nodeIds) {
  const ids = Array.isArray(nodeIds) ? nodeIds : [nodeIds];
  selectedNodeIds = new Set(ids);
  selectedNodeId = ids[0] || null;
  highlightLinks.clear();
  refreshSelection();

  const filtered = investigationMode === "details"
    ? visibleDetailsFor(ids)
    : visibleGraphFor(ids, hopDepth);
  Graph.graphData(filtered);

  updateControls();
  fitCurrentGraph(550, 65);
}

function leaveInvestigation() {
  selectedNodeId = null;
  selectedNodeIds.clear();
  highlightLinks.clear();

  Graph.graphData(fullData);
  refreshSelection();
  updateControls();
}

function goBack() {
  const saved = browsingCamera;

  leaveInvestigation();
  browsingCamera = null;

  // Return to exactly where the user was browsing before drill-down.
  if (saved) {
    restoreCamera(saved, 700);
  }
}

function resetView() {
  leaveInvestigation();
  browsingCamera = null;

  // Reset means the initial/default full-graph view, not the
  // last browsing position.
  if (initialCamera) {
    restoreCamera(initialCamera, 800);
  } else {
    fitCurrentGraph(800, 70);
  }
}

Graph.onNodeClick(node => {
  // Save the user's current full-graph browsing view only once,
  // when entering investigation mode. 1-hop/2-hop switches must
  // not overwrite it.
  if (!isInvestigating()) {
    saveBrowsingCamera();
  }

  // Every new selection starts in the most focused view.
  hopDepth = 1;
  investigationMode = "hop1";
  showNeighborhood(node.id);
});

hop1Button.addEventListener("click", event => {
  event.stopPropagation();
  hopDepth = 1;
  investigationMode = "hop1";
  updateControls();

  if (isInvestigating()) {
    showNeighborhood([...selectedNodeIds]);
  }
});

detailsButton.addEventListener("click", event => {
  event.stopPropagation();
  investigationMode = "details";
  updateControls();

  if (isInvestigating()) {
    showNeighborhood([...selectedNodeIds]);
  }
});

hop2Button.addEventListener("click", event => {
  event.stopPropagation();
  hopDepth = 2;
  investigationMode = "hop2";
  updateControls();

  if (isInvestigating()) {
    showNeighborhood([...selectedNodeIds]);
  }
});

backButton.addEventListener("click", event => {
  event.stopPropagation();
  goBack();
});

resetViewButton.addEventListener("click", event => {
  event.stopPropagation();
  resetView();
});

window.addEventListener("keydown", event => {
  if (event.key === "Escape" && isInvestigating()) {
    goBack();
  }
});

renderNodeBrowser();
updateControls();


/* ---------------------------------------------------------
 * INITIAL CAMERA
 * --------------------------------------------------------- */

setTimeout(() => {
  Graph.zoomToFit(900, 70);

  // zoomToFit animates. Capture the resulting camera only after
  // the initial transition has settled; Reset view returns here.
  setTimeout(() => {
    initialCamera = captureCamera();
  }, 1000);
}, 1800);

</script>

</body>
</html>
EOF


cd "$TMPDIR"

python3 -m http.server "$PORT" >/dev/null 2>&1 &
SERVER_PID=$!

sleep 0.5

URL="http://127.0.0.1:${PORT}/"

echo "Opening: $URL"

if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$URL" >/dev/null 2>&1 || true
fi

echo
echo "Ctrl-C to stop."
echo

wait "$SERVER_PID"
