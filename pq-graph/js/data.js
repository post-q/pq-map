
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


