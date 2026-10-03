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

const LINK_AUTO_HIDE_THRESHOLD = 5000;
let linksUserPreference = null;

function linksVisible() {
  if (isInvestigating()) return true;

  if (linksUserPreference !== null) return linksUserPreference;

  // LOD overviews are small enough to always render links.
  if (overviewLodEnabled) return true;

  return fullData.nodes.length < LINK_AUTO_HIDE_THRESHOLD;
}

function linkVisibilityAccessor(link) {
  if (highlightLinks.has(link)) return true;
  return linksVisible();
}


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


/*
 * Search/filter operates over lossless fullData. When an exact HOST/CERT that
 * is hidden inside an overview aggregate matches, temporarily reveal it and
 * its immediate fullData relationships on top of the aggregated overview.
 */
function browserProjectionData() {
  if (!overviewLodEnabled || !hasActiveSearch()) {
    return overviewData;
  }

  const matchedOriginals = fullData.nodes.filter(node => searchMatchIds.has(node.id));
  if (!matchedOriginals.length) return overviewData;

  const hiddenMatchIds = new Set(
    matchedOriginals
      .filter(node => role(node) === "host" || role(node) === "certificate")
      .map(node => node.id)
  );

  if (!hiddenMatchIds.size) {
    return overviewData;
  }

  const nodes = [...overviewData.nodes];
  const nodeIds = new Set(nodes.map(node => node.id));

  for (const node of matchedOriginals) {
    if (!nodeIds.has(node.id)) {
      nodes.push(node);
      nodeIds.add(node.id);
    }
  }

  /*
   * Also reveal immediate neighbours of matched originals so the highlighted
   * node is not floating without context.
   */
  for (const link of fullData.links) {
    const sourceId = endpointId(link.source);
    const targetId = endpointId(link.target);

    if (!hiddenMatchIds.has(sourceId) && !hiddenMatchIds.has(targetId)) continue;

    for (const id of [sourceId, targetId]) {
      const node = nodeById.get(id);
      if (node && !nodeIds.has(id)) {
        nodes.push(node);
        nodeIds.add(id);
      }
    }
  }

  const links = [...overviewData.links];
  const seen = new Set(
    links.map(link => `${endpointId(link.source)}\u0000${relationName(link)}\u0000${endpointId(link.target)}`)
  );

  for (const link of fullData.links) {
    const sourceId = endpointId(link.source);
    const targetId = endpointId(link.target);

    if (!nodeIds.has(sourceId) || !nodeIds.has(targetId)) continue;
    if (!hiddenMatchIds.has(sourceId) && !hiddenMatchIds.has(targetId)) continue;

    const key = `${sourceId}\u0000${relationName(link)}\u0000${targetId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    links.push(freshLink(link));
  }

  return { nodes, links };
}

function refreshBrowserProjection() {
  if (isInvestigating()) return;
  const projection = browserProjectionData();
  currentRenderedNodeCount = projection.nodes.length;

  if (Graph.graphData().nodes === projection.nodes) return;

  setGraphData(projection);
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

  if (node._aggregate) {
    const scale = Math.min(3.5, 1 + Math.log10(Math.max(2, node._aggregateCount || 2)));
    size *= scale;
  }

  if (isSelectedNode(node)) {
    return Math.max(size * 4, 8);
  }

  if (!isInvestigating() && hasActiveSearch() && isSearchMatch(node)) {
    return Math.max(size * 2.2, 4);
  }

  return size;
}



const LARGE_GRAPH_LABEL_THRESHOLD = 300;
const LARGE_GRAPH_FORCE_THRESHOLD = 1000;
const SEARCH_SPRITE_CAP = 300;
const MAX_BROWSER_ROWS = 300;
let currentRenderedNodeCount = overviewData.nodes.length;

let visibleNodeIds = new Set(overviewData.nodes.map(node => node.id));

function setGraphData(graphData) {
  visibleNodeIds = new Set(graphData.nodes.map(node => node.id));
  Graph.graphData(graphData);
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


const SMALL_ROLE_LABELS = new Set([
  "root_ca",
  "intermediate_ca",
  "key_exchange",
  "symmetric",
  "certificate_key",
  "certificate_signature",
  "service"
]);

function shouldShowText(node) {
  // Always keep the selected entity readable.
  if (isSelectedNode(node)) return true;

  // Labels are useful in small investigation graphs, but thousands of
  // SpriteText instances dominate large 2-hop render time.
  if (isInvestigating()) {
    return currentRenderedNodeCount <= LARGE_GRAPH_LABEL_THRESHOLD;
  }

  if (hasActiveSearch() && isSearchMatch(node)) {
    return searchMatchIds.size <= SEARCH_SPRITE_CAP;
  }

  if (node._aggregate) return true;

  return SMALL_ROLE_LABELS.has(role(node));
}

function makeText(node) {
  if (!shouldShowText(node)) {
    return null;
  }

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
    sprite.color = "#ffffff";
    sprite.textHeight = Math.max(textHeight(node) * 1.35, 2.8);
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
    document.getElementById("graph"),
    {
      rendererConfig: {
        powerPreference: "high-performance"
      }
    }
  )

  .graphData(overviewData)

  .nodeVal(nodeSize)

  .nodeColor(nodeColor)

  /*
   * Sphere + on-demand SpriteText.
   */
  .nodeThreeObject(makeText)

  .nodeThreeObjectExtend(true)

  .nodeLabel(node => {

  const connections = [];

  for (const link of (node.links || [])) {

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

  if (node._aggregate) {
    const kind = node._aggregateRole === "host" ? "HOST GROUP" : "CERT GROUP";
    const lines = [
      `<b>${kind} · ${node.label}</b>`,
      "",
      `<span style="opacity:.62">${node._aggregateCount} underlying nodes</span>`
    ];

    if (connections.length) {
      lines.push("");
      for (const c of connections.slice(0, 24)) {
        lines.push(
          `<span style="opacity:.55">[${relationForPerspective(c.relation, c.outgoing)}]</span> ` +
          `${displayLabel(c.node)}`
        );
      }
      if (connections.length > 24) {
        lines.push(`<span style="opacity:.45">… ${connections.length - 24} more relationships</span>`);
      }
    }

    return lines.join("<br>");
  }

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

  .linkVisibility(linkVisibilityAccessor)

  /*
   * No particles.
   */
  .linkDirectionalParticles(0)

  /*
   * Run enough force iterations to settle the semantic layout before the first
   * frame, then stop after a bounded number of rendered ticks. This prevents a
   * 5k+ graph from spending seconds continuously simulating in the browser.
   */
  .warmupTicks(20)
  .cooldownTicks(20)

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
 * --------------------------------------------------------- */

function refreshHighlight() {
  Graph
    .linkVisibility(Graph.linkVisibility())
    .linkOpacity(Graph.linkOpacity());
}

function refreshNodeVisuals() {
  Graph
    .nodeVal(Graph.nodeVal())
    .nodeColor(Graph.nodeColor());
}

let spriteOverlayActive = false;
let spriteDigestTimer = null;

function refreshSelection() {
  refreshNodeVisuals();
  Graph.linkOpacity(Graph.linkOpacity());

  if (currentRenderedNodeCount < LARGE_GRAPH_FORCE_THRESHOLD) {
    clearTimeout(spriteDigestTimer);
    Graph.nodeThreeObject(Graph.nodeThreeObject());
    return;
  }

  const overlayNeeded =
    !isInvestigating() &&
    hasActiveSearch() &&
    searchMatchIds.size <= SEARCH_SPRITE_CAP;

  if (overlayNeeded || spriteOverlayActive) {
    clearTimeout(spriteDigestTimer);
    spriteDigestTimer = setTimeout(() => {
      Graph.nodeThreeObject(Graph.nodeThreeObject());
    }, 400);
  }

  spriteOverlayActive = overlayNeeded;
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
const linksButton = document.getElementById("links");
const selectionLabel = document.getElementById("selection");
const nodeSearchInput = document.getElementById("node-search");
const nodeList = document.getElementById("node-list");
const nodeBrowserCount = document.getElementById("node-browser-count");
const nodeRoleFilters = document.getElementById("node-role-filters");

