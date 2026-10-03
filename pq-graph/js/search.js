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

const haystackCache = new Map();

function cachedHaystack(node) {
  let haystack = haystackCache.get(node.id);

  if (haystack === undefined) {
    haystack = searchableNodeText(node);
    haystackCache.set(node.id, haystack);
  }

  return haystack;
}

const tokenPatternCache = new Map();

function tokenRegExp(token) {
  const pattern = token.includes("*") ? token : `*${token}*`;
  let regExp = tokenPatternCache.get(pattern);

  if (!regExp) {
    regExp = globToRegExp(pattern);
    tokenPatternCache.set(pattern, regExp);
  }

  return regExp;
}

function nodeMatchesQuery(node, rawQuery) {
  const tokens = queryTokens(rawQuery);
  if (!tokens.length) return true;

  const haystack = cachedHaystack(node);

  // Search terms are ANDed. Each term is a substring unless it contains '*'.
  // Example: "host allegro" => node must match both "host" and "allegro".
  return tokens.every(token => tokenRegExp(token).test(haystack));
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

  const descendantCounts = new Map();

  for (const node of fullData.nodes) {
    if (role(node) !== "host" || !node.label) continue;

    const parts = node.label.split(".");
    for (let i = 1; i < parts.length; i++) {
      const suffix = parts.slice(i).join(".");
      descendantCounts.set(suffix, (descendantCounts.get(suffix) || 0) + 1);
    }
  }

  let best = null;
  let bestDescendants = -1;

  for (const candidate of hosts) {
    const descendants = descendantCounts.get(candidate.label) || 0;

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
  refreshBrowserProjection();

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

    const rows = browserRows(matches);
    const overflow = Math.max(0, rows.length - MAX_BROWSER_ROWS);

    for (const row of rows.slice(0, MAX_BROWSER_ROWS)) {
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

    if (overflow > 0) {
      const more = document.createElement("div");
      more.className = "node-list-more";
      more.textContent = `… ${overflow} more — refine the search`;
      fragment.appendChild(more);
    }

    nodeList.appendChild(fragment);
  }

  refreshSelection();
}

let nodeSearchTimer = null;

function updateNodeSearch() {
  nodeSearchQuery = nodeSearchInput.value;

  // Rebuilding the result list and refreshing graph objects on every keystroke
  // is unnecessarily expensive for inventories with thousands of nodes.
  clearTimeout(nodeSearchTimer);
  nodeSearchTimer = setTimeout(() => {
    renderNodeBrowser();
  }, 150);
}

nodeSearchInput.addEventListener("input", updateNodeSearch);
nodeSearchInput.addEventListener("keydown", event => {
  // Keep typing/search shortcuts from leaking into graph-level key handling.
  event.stopPropagation();

  if (event.key === "Escape" && nodeSearchInput.value) {
    nodeSearchInput.value = "";
    clearTimeout(nodeSearchTimer);
    nodeSearchQuery = "";
    renderNodeBrowser();
  }
});

renderRoleFilters();

