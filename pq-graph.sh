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
  </style>

  <script src="https://cdn.jsdelivr.net/npm/3d-force-graph"></script>
</head>

<body>

<div id="graph"></div>

<div id="legend">
  Interactive topology of observed cryptographic relationships.
</div>

<div id="controls">
  <div id="selection">Full graph</div>
  <button id="hop1" disabled title="Select a node first; then show its direct neighbours">1 hop</button>
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
 * DISPLAY PROJECTION / HOST COMPACTION
 *
 * Keep graph.json lossless. For presentation only, compact the
 * common pair foo.example + www.foo.example into one HOST node
 * when both names expose the same observed crypto posture.
 * Certificate nodes remain distinct and both stay connected to
 * the compacted host.
 * --------------------------------------------------------- */

function rawEndpointId(endpoint) {
  return typeof endpoint === "object" ? endpoint.id : endpoint;
}

function relationName(link) {
  return link.label || link.type || "";
}

function normalizedBaseHost(label) {
  if (!label) return null;
  return label.startsWith("www.") ? label.slice(4) : label;
}

function observedCryptoSignature(hostId, links) {
  const relevant = new Set([
    "exposes",
    "negotiated_kx",
    "symmetric_cipher"
  ]);

  const values = [];

  for (const link of links) {
    const sourceId = rawEndpointId(link.source);
    const targetId = rawEndpointId(link.target);
    const relation = relationName(link);

    if (!relevant.has(relation)) continue;
    if (sourceId !== hostId && targetId !== hostId) continue;

    const otherId = sourceId === hostId ? targetId : sourceId;
    values.push(`${relation}:${otherId}`);
  }

  values.sort();
  return values.join("|");
}

function certificateLabelsForHost(hostId, links, canonicalNodeById) {
  const labels = new Set();

  for (const link of links) {
    const sourceId = rawEndpointId(link.source);
    const targetId = rawEndpointId(link.target);
    const relation = relationName(link);

    let certificateId = null;

    if (relation === "presents_certificate" && sourceId === hostId) {
      certificateId = targetId;
    } else if (relation === "certificate_for" && targetId === hostId) {
      certificateId = sourceId;
    }

    if (!certificateId) continue;

    const cert = canonicalNodeById.get(certificateId);
    if (cert) labels.add(cert.label || cert.id);
  }

  return [...labels].sort();
}

function buildDisplayProjection(canonical) {
  const canonicalNodeById = new Map(
    canonical.nodes.map(node => [node.id, node])
  );

  const hostsByBase = new Map();

  for (const node of canonical.nodes) {
    if (node.type !== "host") continue;

    const base = normalizedBaseHost(node.label);
    if (!base) continue;

    if (!hostsByBase.has(base)) hostsByBase.set(base, []);
    hostsByBase.get(base).push(node);
  }

  const replacementId = new Map();
  const aggregateNodes = new Map();

  for (const [base, hosts] of hostsByBase) {
    const apex = hosts.find(node => node.label === base);
    const www = hosts.find(node => node.label === `www.${base}`);

    if (!apex || !www) continue;

    const apexSignature = observedCryptoSignature(apex.id, canonical.links);
    const wwwSignature = observedCryptoSignature(www.id, canonical.links);

    // Only compact when there is actual observed crypto/service data and
    // the two hostnames are operationally equivalent in this view.
    if (!apexSignature || apexSignature !== wwwSignature) continue;

    const aggregateId = `host-group:${base}`;
    const aliases = [apex, www]
      .sort((a, b) => a.label.localeCompare(b.label))
      .map(host => ({
        id: host.id,
        label: host.label,
        certificates: certificateLabelsForHost(
          host.id,
          canonical.links,
          canonicalNodeById
        )
      }));

    aggregateNodes.set(aggregateId, {
      ...apex,
      id: aggregateId,
      label: base,
      aliases,
      memberIds: aliases.map(alias => alias.id),
      compactedHost: true
    });

    replacementId.set(apex.id, aggregateId);
    replacementId.set(www.id, aggregateId);
  }

  const nodes = [];

  for (const node of canonical.nodes) {
    const replacement = replacementId.get(node.id);

    if (!replacement) {
      nodes.push({ ...node });
      continue;
    }

    if (!nodes.some(existing => existing.id === replacement)) {
      nodes.push(aggregateNodes.get(replacement));
    }
  }

  const links = [];
  const seenLinks = new Set();

  for (const link of canonical.links) {
    const originalSource = rawEndpointId(link.source);
    const originalTarget = rawEndpointId(link.target);
    const source = replacementId.get(originalSource) || originalSource;
    const target = replacementId.get(originalTarget) || originalTarget;

    // A host-pair relation collapsed onto itself carries no information.
    if (source === target) continue;

    const relation = relationName(link);
    const key = `${source}\u0000${target}\u0000${relation}`;
    if (seenLinks.has(key)) continue;
    seenLinks.add(key);

    links.push({
      ...link,
      source,
      target
    });
  }

  return { nodes, links };
}

const data = buildDisplayProjection(canonicalData);

const nodeById = new Map(
  data.nodes.map(node => [node.id, node])
);

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
    return "issuer";
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

    default:
      return node.label || node.id;
  }
}


/* ---------------------------------------------------------
 * SEMANTIC POSITION
 * --------------------------------------------------------- */

function targetX(node) {

  switch (role(node)) {

    case "issuer":
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

    case "issuer":
      return 90;

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
let hopDepth = 1;


/* ---------------------------------------------------------
 * COLORS
 * --------------------------------------------------------- */

function baseColor(node) {

  switch (role(node)) {

    case "host":
      return "#7ca7ff";

    case "certificate":
      return "#c9c9d2";

    case "issuer":
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


function nodeColor(node) {
  return node.id === selectedNodeId ? "#ffffff" : baseColor(node);
}


/* ---------------------------------------------------------
 * SIZE
 * --------------------------------------------------------- */

function nodeSize(node) {

  let size;

  switch (role(node)) {
    case "host": size = 1.2; break;
    case "certificate": size = 1.1; break;
    case "issuer": size = 5; break;
    case "certificate_key":
    case "certificate_signature": size = 3; break;
    case "key_exchange": size = 5; break;
    case "symmetric":
    case "service": size = 4; break;
    default: size = 2;
  }

  return node.id === selectedNodeId
    ? Math.max(size * 4, 8)
    : size;
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

    case "issuer":
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

  const selected = node.id === selectedNodeId;
  const text = selected
    ? `● SELECTED\n${displayLabel(node)}`
    : displayLabel(node);

  const sprite = new SpriteText(text);
  sprite.material.depthWrite = false;

  if (selected) {
    sprite.color = "#ffffff";
    sprite.textHeight = 6;
    sprite.center.y = -1.35;
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
  .linkOpacity(0.12)

  .linkWidth(link =>
    highlightLinks.has(link)
      ? 2.5
      : 0.20
  )

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

  Graph.linkWidth(
    Graph.linkWidth()
  );
}

function refreshSelection() {
  Graph
    .nodeVal(Graph.nodeVal())
    .nodeColor(Graph.nodeColor())
    .nodeThreeObject(Graph.nodeThreeObject());
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
 * Click a node to isolate its 1-hop / 2-hop neighbourhood.
 * Back restores the full graph and the camera position from before drill-down.
 * Reset view restores the full graph and the initial/default camera.
 * --------------------------------------------------------- */

let browsingCamera = null;
let initialCamera = null;

const hop1Button = document.getElementById("hop1");
const hop2Button = document.getElementById("hop2");
const backButton = document.getElementById("back");
const resetViewButton = document.getElementById("resetView");
const selectionLabel = document.getElementById("selection");

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

function collectNeighborhood(startId, depth) {
  const visited = new Set([startId]);
  let frontier = new Set([startId]);

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

function visibleGraphFor(startId, depth) {
  const visibleIds = collectNeighborhood(startId, depth);

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

function updateControls() {
  const investigating = Boolean(selectedNodeId);

  hop1Button.disabled = !investigating;
  hop2Button.disabled = !investigating;
  backButton.hidden = !investigating;

  // A hop button is active only when a node is actually isolated.
  // This avoids the misleading initial state "1 hop" + full graph.
  hop1Button.classList.toggle("active", investigating && hopDepth === 1);
  hop2Button.classList.toggle("active", investigating && hopDepth === 2);

  if (!investigating) {
    selectionLabel.textContent = "Full graph";
    return;
  }

  const node = nodeById.get(selectedNodeId);
  selectionLabel.innerHTML = node
    ? `<strong>${displayLabel(node)}</strong>`
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

function showNeighborhood(nodeId) {
  selectedNodeId = nodeId;
  highlightLinks.clear();
  refreshSelection();

  const filtered = visibleGraphFor(nodeId, hopDepth);
  Graph.graphData(filtered);

  updateControls();
  fitCurrentGraph(550, 65);
}

function leaveInvestigation() {
  selectedNodeId = null;
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
  if (!selectedNodeId) {
    saveBrowsingCamera();
  }

  // Every new selection starts in the most focused view.
  hopDepth = 1;
  showNeighborhood(node.id);
});

hop1Button.addEventListener("click", event => {
  event.stopPropagation();
  hopDepth = 1;
  updateControls();

  if (selectedNodeId) {
    showNeighborhood(selectedNodeId);
  }
});

hop2Button.addEventListener("click", event => {
  event.stopPropagation();
  hopDepth = 2;
  updateControls();

  if (selectedNodeId) {
    showNeighborhood(selectedNodeId);
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
  if (event.key === "Escape" && selectedNodeId) {
    goBack();
  }
});

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
