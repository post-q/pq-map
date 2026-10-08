/*
 * 3d-force-graph mutates link.source/link.target from IDs into node objects.
 * Never pass the canonical fullData link objects directly into a temporary
 * graph projection. Build fresh link objects with normalized endpoint IDs so
 * switching overview -> search -> drill-down cannot leave stale references.
 */
function freshLink(link) {
  return {
    ...link,
    source: endpointId(link.source),
    target: endpointId(link.target)
  };
}

function materializeSubgraph(visibleIds) {
  const nodes = fullData.nodes.filter(node => visibleIds.has(node.id));
  const links = fullData.links
    .filter(link =>
      visibleIds.has(endpointId(link.source)) &&
      visibleIds.has(endpointId(link.target))
    )
    .map(freshLink);

  return { nodes, links };
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
  return materializeSubgraph(visibleIds);
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

  return materializeSubgraph(visibleIds);
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

  linksButton.disabled = investigating;
  linksButton.classList.toggle("active", !investigating && linksVisible());

  // A hop button is active only when a node is actually isolated.
  // This avoids the misleading initial state "1 hop" + full graph.
  hop1Button.classList.toggle("active", investigating && investigationMode === "hop1");
  detailsButton.classList.toggle("active", investigating && investigationMode === "details");
  hop2Button.classList.toggle("active", investigating && investigationMode === "hop2");

  if (!investigating) {
    const stats = overviewProjection.stats;
    selectionLabel.textContent = stats.lodEnabled
      ? `Overview · ${overviewData.nodes.length}/${stats.totalNodes} nodes`
      : "Overview";
    return;
  }

  const selectedNodes = [...selectedNodeIds]
    .map(id => nodeById.get(id))
    .filter(Boolean);

  selectionLabel.innerHTML = selectedNodes.length
    ? selectedNodes.map(node => `<strong>${redactNodeHtml(node)}</strong>`).join(" + ")
    : "Selection";
}

function fitCurrentGraph(duration = 500, padding = 55) {
  requestAnimationFrame(() => {
    const nodeCount = Graph.graphData().nodes.length;

    // Reheating a multi-thousand-node 2-hop graph is expensive and usually
    // produces little visual benefit. Small graphs still get the animated
    // semantic settling behaviour.
    if (nodeCount < LARGE_GRAPH_FORCE_THRESHOLD) {
      Graph.d3ReheatSimulation();
    }

    setTimeout(() => {
      Graph.zoomToFit(duration, padding);
    }, nodeCount < LARGE_GRAPH_FORCE_THRESHOLD ? 120 : 30);
  });
}

function showNeighborhood(nodeIds) {
  const ids = Array.isArray(nodeIds) ? nodeIds : [nodeIds];
  stopDemo();

  const filtered = investigationMode === "details"
    ? visibleDetailsFor(ids)
    : visibleGraphFor(ids, hopDepth);

  selectedNodeIds = new Set(ids);
  selectedNodeId = ids[0] || null;
  highlightLinks.clear();

  // Switch topology first. Refreshing node objects before graphData() used to
  // refresh the aggregated overview rather than the real drill-down graph.
  currentRenderedNodeCount = filtered.nodes.length;
  setGraphData(filtered);

  refreshSelection();
  updateControls();
  fitCurrentGraph(550, 65);
}

function leaveInvestigation() {
  selectedNodeId = null;
  selectedNodeIds.clear();
  highlightLinks.clear();

  const projection = browserProjectionData();
  currentRenderedNodeCount = projection.nodes.length;
  setGraphData(projection);
  refreshSelection();
  updateControls();
}

function goBack() {
  const saved = browsingCamera;

  stopDemo();
  leaveInvestigation();
  browsingCamera = null;

  // Return to exactly where the user was browsing before drill-down.
  if (saved) {
    restoreCamera(saved, 700);
  }
}

function resetView() {
  stopDemo();
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

function showAggregateMembers(node) {
  const memberIds = Array.isArray(node.memberIds) ? node.memberIds : [];
  if (!memberIds.length) return;

  stopDemo();

  const MAX_EXPANDED_MEMBERS = 250;
  const selectedMembers = memberIds.slice(0, MAX_EXPANDED_MEMBERS);
  const visibleIds = new Set(selectedMembers);

  for (const id of selectedMembers) {
    for (const neighbourId of adjacency.get(id) || []) {
      visibleIds.add(neighbourId);
    }
  }

  const { nodes, links } = materializeSubgraph(visibleIds);

  selectedNodeIds = new Set(selectedMembers);
  selectedNodeId = selectedMembers[0] || null;
  highlightLinks.clear();

  currentRenderedNodeCount = nodes.length;
  setGraphData({ nodes, links });
  refreshSelection();
  updateControls();
  fitCurrentGraph(550, 65);
}

Graph.onNodeClick(node => {
  // Save the user's current overview browsing view only once,
  // when entering investigation mode.
  if (!isInvestigating()) {
    saveBrowsingCamera();
  }

  if (node._aggregate) {
    investigationMode = "hop1";
    hopDepth = 1;
    showAggregateMembers(node);
    return;
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

linksButton.addEventListener("click", event => {
  event.stopPropagation();

  if (isInvestigating()) return;

  linksUserPreference = !linksVisible();
  updateControls();

  Graph.linkVisibility(Graph.linkVisibility());
});

window.addEventListener("keydown", event => {
  if (event.repeat) return;

  if (
    (event.key === "i" || event.key === "I") &&
    !event.ctrlKey && !event.metaKey && !event.altKey
  ) {
    toggleRedaction();
    return;
  }

  if (
    (event.key === "d" || event.key === "D") &&
    !event.ctrlKey && !event.metaKey && !event.altKey
  ) {
    if (demoRotating) {
      stopDemo();
    } else {
      startDemo();
    }
    return;
  }

  if (
    (event.key === "c" || event.key === "C") &&
    !event.ctrlKey && !event.metaKey && !event.altKey
  ) {
    document.body.classList.toggle("clean");
    return;
  }

  if (event.key === "Escape" && isInvestigating()) {
    goBack();
  }
});

