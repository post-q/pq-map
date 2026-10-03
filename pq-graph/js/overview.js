/* ---------------------------------------------------------
 * ROLE
 * --------------------------------------------------------- */

function role(node) {
  if (node._role) return node._role;

  let r;

  if (node._aggregateRole === "host" || node.group === "host_cluster") {
    r = "host";
  } else if (node._aggregateRole === "certificate" || node.group === "certificate_cluster") {
    r = "certificate";
  } else if (node.type === "host") {
    r = "host";
  } else if (node.group === "certificate") {
    r = "certificate";
  } else if (node.group === "issuer") {
    r = node._caRole === "root" ? "root_ca" : "intermediate_ca";
  } else if (node.group === "certificate_key") {
    r = "certificate_key";
  } else if (node.group === "certificate_signature") {
    r = "certificate_signature";
  } else if (node.group === "key_exchange") {
    r = "key_exchange";
  } else if (node.group === "symmetric") {
    r = "symmetric";
  } else if (
    node.type === "service" ||
    node.group === "tcp_service"
  ) {
    r = "service";
  } else {
    r = "other";
  }

  node._role = r;
  return r;
}

/* ---------------------------------------------------------
 * OVERVIEW / CARDINALITY-DRIVEN LOD
 *
 * Below 15000 nodes render the complete graph.
 *
 * At 15000+ nodes:
 *   - keep every low-cardinality semantic node 1:1,
 *   - aggregate only HOST and CERTIFICATE nodes,
 *   - rewire and deduplicate links through those aggregates.
 *
 * The complete graph remains lossless in fullData and continues to drive
 * search, 1-hop, 2-hop and Details views.
 * --------------------------------------------------------- */

const OVERVIEW_LOD_THRESHOLD = 15000;
const overviewLodEnabled = fullData.nodes.length >= OVERVIEW_LOD_THRESHOLD;

/*
 * Adaptive aggregation:
 *   < 1k nodes   -> disabled entirely
 *   1k-5k       -> aggregate only larger groups
 *   5k-10k      -> moderate aggregation
 *   > 10k       -> stronger aggregation
 *
 * HOSTs are kept less aggressively aggregated than before; CERTs can use a
 * slightly lower threshold because certificate-profile repetition is common.
 */
function aggregationThresholds(totalNodes) {
  if (totalNodes < 1000) {
    return { hostMin: Infinity, certMin: Infinity };
  }

  if (totalNodes < 5000) {
    return { hostMin: 10, certMin: 25 };
  }

  if (totalNodes < 10000) {
    return { hostMin: 10, certMin: 25 };
  }

  return { hostMin: 5, certMin: 3 };
}

const aggregationThreshold = aggregationThresholds(fullData.nodes.length);

/*
 * HOST grouping heuristic.
 *
 * For ordinary domains use the last two labels (example.com).
 * For common ccTLD second-level namespaces use three labels
 * (example.gov.pl, example.com.pl, example.co.uk).
 *
 * This is intentionally a presentation heuristic, not a PSL implementation.
 * It only affects the 1000+ node overview; fullData is untouched.
 */
const COMMON_SECOND_LEVEL_SUFFIXES = new Set([
  "ac", "co", "com", "edu", "gov", "mil", "net", "org"
]);

function hostClusterKey(node) {
  const hostname = String(node.label || node.id || "")
    .replace(/^HOST\s*·\s*/i, "")
    .replace(/\.$/, "")
    .toLowerCase();

  const parts = hostname.split(".").filter(Boolean);
  if (parts.length <= 2) return hostname || node.id;

  const tld = parts[parts.length - 1];
  const sld = parts[parts.length - 2];

  if (tld.length === 2 && COMMON_SECOND_LEVEL_SUFFIXES.has(sld) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }

  return parts.slice(-2).join(".");
}

function aggregateNeighborLabels(nodeId, relations) {
  const labels = [];

  for (const link of nodeById.get(nodeId)?.links || []) {
    const relation = relationName(link);
    if (!relations.has(relation)) continue;

    const sourceId = endpointId(link.source);
    const targetId = endpointId(link.target);
    const otherId = sourceId === nodeId ? targetId : sourceId;
    const other = nodeById.get(otherId);
    if (!other) continue;

    labels.push(String(other.label || other.id));
  }

  return [...new Set(labels)].sort();
}

const certificateProfileCache = new Map();

function certificateProfile(nodeId) {
  let profile = certificateProfileCache.get(nodeId);

  if (!profile) {
    profile = {
      issuer: aggregateNeighborLabels(nodeId, new Set(["issued_by"])),
      key: aggregateNeighborLabels(nodeId, new Set(["cert_key"])),
      signature: aggregateNeighborLabels(nodeId, new Set(["cert_signature"]))
    };
    certificateProfileCache.set(nodeId, profile);
  }

  return profile;
}

/*
 * Certificate clusters represent the same trust/crypto profile:
 * issuer chain entry + certificate key + certificate signature.
 *
 * SAN/hostname coverage is deliberately NOT part of the cluster key; including
 * it would make most certificate nodes unique and defeat overview reduction.
 */
function certificateClusterKey(node) {
  return JSON.stringify(certificateProfile(node.id));
}

function certificateClusterLabel(node) {
  const profile = certificateProfile(node.id);

  const parts = [
    profile.issuer[0],
    profile.key[0],
    profile.signature[0]
  ].filter(Boolean);

  return parts.length ? parts.join(" · ") : "certificate profile";
}

function countNodesByRole(nodes) {
  const counts = new Map();
  for (const node of nodes) {
    const r = role(node);
    counts.set(r, (counts.get(r) || 0) + 1);
  }
  return counts;
}

function roleBreakdownHtml(nodes) {
  const labels = {
    host: "HOST",
    certificate: "CERT",
    service: "SERVICE",
    intermediate_ca: "CA",
    root_ca: "ROOT CA",
    key_exchange: "KX",
    symmetric: "CIPHER",
    certificate_key: "CERT KEY",
    certificate_signature: "SIGNATURE",
    other: "OTHER"
  };

  const counts = countNodesByRole(nodes);
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([r, count]) => `${labels[r] || r.toUpperCase()} ${count}`)
    .join(" · ");
}

function buildOverviewData() {
  if (!overviewLodEnabled) {
    const totalHosts = fullData.nodes.filter(node => role(node) === "host").length;
    const totalCertificates = fullData.nodes.filter(node => role(node) === "certificate").length;

    return {
      nodes: fullData.nodes,
      links: fullData.links,
      stats: {
        totalNodes: fullData.nodes.length,
        totalLinks: fullData.links.length,
        totalHosts,
        totalCertificates,
        hostClusters: totalHosts,
        certificateClusters: totalCertificates,
        hostClusterMin: null,
        certificateClusterMin: null,
        lodEnabled: false
      }
    };
  }

  const hostGroups = new Map();
  const certificateGroups = new Map();

  for (const node of fullData.nodes) {
    const r = role(node);

    if (r === "host") {
      const key = hostClusterKey(node);
      if (!hostGroups.has(key)) hostGroups.set(key, []);
      hostGroups.get(key).push(node);
      continue;
    }

    if (r === "certificate") {
      const key = certificateClusterKey(node);
      if (!certificateGroups.has(key)) certificateGroups.set(key, []);
      certificateGroups.get(key).push(node);
    }
  }

  const aggregateByOriginalId = new Map();
  const aggregateNodes = [];

  for (const [key, members] of hostGroups) {
    /*
     * Keep small groups lossless. Only groups large enough to materially reduce
     * the overview are replaced by a synthetic cluster.
     */
    if (members.length < aggregationThreshold.hostMin) {
      for (const member of members) {
        aggregateByOriginalId.set(member.id, member);
      }
      continue;
    }

    const aggregate = {
      id: `cluster:host:${key}`,
      label: `${key} · ${members.length} hosts`,
      type: "host_cluster",
      group: "host_cluster",
      _aggregate: true,
      _aggregateRole: "host",
      _aggregateCount: members.length,
      memberIds: members.map(node => node.id)
    };

    aggregateNodes.push(aggregate);
    for (const member of members) {
      aggregateByOriginalId.set(member.id, aggregate);
    }
  }

  for (const [key, members] of certificateGroups) {
    if (members.length < aggregationThreshold.certMin) {
      for (const member of members) {
        aggregateByOriginalId.set(member.id, member);
      }
      continue;
    }

    const profile = certificateClusterLabel(members[0]);
    const aggregate = {
      id: `cluster:certificate:${aggregateNodes.length}`,
      label: `${members.length} certs · ${profile}`,
      type: "pki",
      group: "certificate_cluster",
      _aggregate: true,
      _aggregateRole: "certificate",
      _aggregateCount: members.length,
      _aggregateKey: key,
      memberIds: members.map(node => node.id)
    };

    aggregateNodes.push(aggregate);
    for (const member of members) {
      aggregateByOriginalId.set(member.id, aggregate);
    }
  }

  /*
   * Every non-HOST / non-CERT node is preserved exactly as-is.
   */
  const passthroughNodes = fullData.nodes.filter(node => {
    const r = role(node);
    return r !== "host" && r !== "certificate";
  });

  for (const node of fullData.nodes) {
    const r = role(node);
    if (r !== "host" && r !== "certificate") {
      aggregateByOriginalId.set(node.id, node);
    }
  }

  /*
   * Include original singleton HOST/CERT nodes plus synthetic aggregates.
   */
  const singletonNodes = [];
  const seenSingletonIds = new Set();

  for (const original of fullData.nodes) {
    const r = role(original);
    if (r !== "host" && r !== "certificate") continue;

    const mapped = aggregateByOriginalId.get(original.id);
    if (mapped === original && !seenSingletonIds.has(original.id)) {
      singletonNodes.push(original);
      seenSingletonIds.add(original.id);
    }
  }

  const nodes = [
    ...passthroughNodes,
    ...singletonNodes,
    ...aggregateNodes
  ];

  /*
   * Rewire original links through aggregate endpoints and deduplicate them.
   * Preserve relation labels/types so overview semantics remain intact.
   */
  const links = [];
  const seenLinks = new Set();

  for (const link of fullData.links) {
    const sourceId = endpointId(link.source);
    const targetId = endpointId(link.target);

    const mappedSource = aggregateByOriginalId.get(sourceId);
    const mappedTarget = aggregateByOriginalId.get(targetId);

    if (!mappedSource || !mappedTarget) continue;
    if (mappedSource.id === mappedTarget.id) continue;

    const relation = relationName(link);
    const dedupeKey = `${mappedSource.id}\u0000${relation}\u0000${mappedTarget.id}`;
    if (seenLinks.has(dedupeKey)) continue;
    seenLinks.add(dedupeKey);

    links.push({
      ...link,
      source: mappedSource.id,
      target: mappedTarget.id,
      _aggregated: mappedSource.id !== sourceId || mappedTarget.id !== targetId
    });
  }

  return {
    nodes,
    links,
    stats: {
      totalNodes: fullData.nodes.length,
      totalLinks: fullData.links.length,
      totalHosts: fullData.nodes.filter(node => role(node) === "host").length,
      totalCertificates: fullData.nodes.filter(node => role(node) === "certificate").length,
      hostClusters: [...hostGroups.values()].reduce(
        (count, members) =>
          count + (members.length < aggregationThreshold.hostMin ? members.length : 1),
        0
      ),
      certificateClusters: [...certificateGroups.values()].reduce(
        (count, members) =>
          count + (members.length < aggregationThreshold.certMin ? members.length : 1),
        0
      ),
      hostClusterMin: aggregationThreshold.hostMin,
      certificateClusterMin: aggregationThreshold.certMin,
      lodEnabled: true
    }
  };
}

const overviewProjection = buildOverviewData();
const overviewData = {
  nodes: overviewProjection.nodes,
  links: overviewProjection.links
};

const overviewStats = overviewProjection.stats;
const legendElement = document.getElementById("legend");
const nodeBreakdown = roleBreakdownHtml(fullData.nodes);

legendElement.innerHTML =
  `Interactive topology of observed cryptographic relationships.` +
  `<br><span style="opacity:.62">${nodeBreakdown}</span>` +
  (overviewStats.lodEnabled
    ? `<br><span style="opacity:.62">Aggregated overview · ${overviewData.nodes.length} / ${overviewStats.totalNodes} nodes · ` +
      `${overviewStats.hostClusters}/${overviewStats.totalHosts} host entries · ` +
      `${overviewStats.certificateClusters}/${overviewStats.totalCertificates} certificate entries · ` +
      `cluster min HOST ${overviewStats.hostClusterMin}, CERT ${overviewStats.certificateClusterMin}.</span>`
    : ``) +
  `<br><span style="opacity:.45">D · demo rotation</span>`;

