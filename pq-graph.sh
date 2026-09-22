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
  <button id="reset" class="primary" disabled title="Restore the complete graph">Expand all</button>
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

const data = await response.json();

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
 * Expand all restores the complete graph.
 * --------------------------------------------------------- */

let browsingCamera = null;

const hop1Button = document.getElementById("hop1");
const hop2Button = document.getElementById("hop2");
const resetButton = document.getElementById("reset");
const selectionLabel = document.getElementById("selection");

function saveBrowsingCamera() {
  const camera = Graph.camera();
  const controls = Graph.controls();

  browsingCamera = {
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
  resetButton.disabled = !investigating;

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

function showAll() {
  const saved = browsingCamera;

  selectedNodeId = null;
  highlightLinks.clear();

  Graph.graphData(fullData);
  refreshSelection();
  updateControls();

  if (saved) {
    browsingCamera = null;

    // Restore the exact camera position and OrbitControls target
    // from before investigation mode. Do not zoomToFit here.
    requestAnimationFrame(() => {
      Graph.cameraPosition(
        saved.position,
        saved.target,
        700
      );
    });
  } else {
    fitCurrentGraph(650, 70);
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

resetButton.addEventListener("click", event => {
  event.stopPropagation();
  showAll();
});

window.addEventListener("keydown", event => {
  if (event.key === "Escape" && selectedNodeId) {
    showAll();
  }
});

updateControls();


/* ---------------------------------------------------------
 * INITIAL CAMERA
 * --------------------------------------------------------- */

setTimeout(() => {
  Graph.zoomToFit(900, 70);
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
