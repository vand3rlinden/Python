"use strict";

/* ---------- DOM build helpers (textContent only - never innerHTML on
   anything that came from VirusTotal / the backend) ---------- */

function el(tag, opts, children) {
  const node = document.createElement(tag);
  if (opts) {
    if (opts.class) node.className = opts.class;
    if (opts.text !== undefined && opts.text !== null) node.textContent = String(opts.text);
    if (opts.attrs) {
      for (const [k, v] of Object.entries(opts.attrs)) {
        if (v !== undefined && v !== null) node.setAttribute(k, v);
      }
    }
  }
  (children || []).forEach((c) => {
    if (c) node.appendChild(c);
  });
  return node;
}

function textOrDash(value) {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

function formatDate(epochSeconds) {
  if (epochSeconds === null || epochSeconds === undefined) return "—";
  try {
    return new Date(epochSeconds * 1000).toLocaleString();
  } catch (err) {
    return "—";
  }
}

function formatBytes(bytes) {
  if (bytes === null || bytes === undefined) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let val = bytes;
  let i = 0;
  while (val >= 1024 && i < units.length - 1) {
    val /= 1024;
    i += 1;
  }
  return `${val.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function kvRow(label, value) {
  return el("div", { class: "kv-row" }, [
    el("span", { class: "k", text: label }),
    el("span", { class: "v", text: textOrDash(value) }),
  ]);
}

/* ---------- client-side throttle: 4 requests / 60s, mirrors VT free tier ---------- */

const MAX_REQUESTS = 4;
const WINDOW_MS = 60_000;
let requestTimestamps = [];
let countdownTimer = null;

function pruneTimestamps() {
  const now = Date.now();
  requestTimestamps = requestTimestamps.filter((t) => now - t < WINDOW_MS);
}

function msUntilSlotFree() {
  pruneTimestamps();
  if (requestTimestamps.length < MAX_REQUESTS) return 0;
  const oldest = Math.min(...requestTimestamps);
  return Math.max(0, WINDOW_MS - (Date.now() - oldest));
}

function setStatus(message) {
  document.getElementById("status-bar").textContent = message || "";
}

function startThrottleCountdown() {
  const btn = document.getElementById("search-btn");
  btn.disabled = true;

  if (countdownTimer) clearInterval(countdownTimer);
  countdownTimer = setInterval(() => {
    const remainingMs = msUntilSlotFree();
    if (remainingMs <= 0) {
      clearInterval(countdownTimer);
      countdownTimer = null;
      btn.disabled = false;
      setStatus("");
      return;
    }
    setStatus(`client throttle: max ${MAX_REQUESTS}/min — next slot in ${Math.ceil(remainingMs / 1000)}s`);
  }, 250);
}

/* ---------- verdict helpers ---------- */

function verdictClass(stats) {
  if (!stats) return "verdict-neutral";
  if (stats.malicious > 0) return "verdict-malicious";
  if (stats.suspicious > 0) return "verdict-suspicious";
  return "verdict-clean";
}

function reputationClass(rep) {
  if (rep === null || rep === undefined) return "verdict-neutral";
  if (rep < 0) return "verdict-malicious";
  if (rep === 0) return "verdict-neutral";
  return "verdict-clean";
}

function categoryClass(category) {
  if (category === "malicious") return "verdict-malicious";
  if (category === "suspicious") return "verdict-suspicious";
  if (category === "harmless" || category === "undetected") return "verdict-clean";
  return "verdict-neutral";
}

/* ---------- shared building blocks ---------- */

function buildStatGrid(stats) {
  const tiles = [
    ["malicious", "verdict-malicious"],
    ["suspicious", "verdict-suspicious"],
    ["harmless", "verdict-clean"],
    ["undetected", "verdict-neutral"],
  ];
  return el(
    "div",
    { class: "stat-grid" },
    tiles.map(([key, cls]) =>
      el("div", { class: "stat-tile" }, [
        el("span", { class: `num ${cls}`, text: stats[key] ?? 0 }),
        el("span", { class: "label", text: key }),
      ])
    )
  );
}

function buildChips(items) {
  if (!items || items.length === 0) return null;
  return el(
    "div",
    { class: "chip-row" },
    items.map((t) => el("span", { class: "chip", text: t }))
  );
}

function buildCategories(categories) {
  const entries = Object.entries(categories || {});
  if (entries.length === 0) return null;
  return el(
    "div",
    { class: "chip-row" },
    entries.map(([vendor, cat]) => el("span", { class: "chip", text: `${vendor}: ${cat}` }))
  );
}

function buildEngineTable(engines) {
  if (!engines || engines.length === 0) return null;

  const thead = el("thead", null, [
    el("tr", null, [
      el("th", { text: "Engine" }),
      el("th", { text: "Category" }),
      el("th", { text: "Result" }),
      el("th", { text: "Method" }),
    ]),
  ]);

  const tbody = el(
    "tbody",
    null,
    engines.map((e) =>
      el("tr", null, [
        el("td", { text: e.engine }),
        el("td", { class: categoryClass(e.category), text: e.category }),
        el("td", { text: textOrDash(e.result) }),
        el("td", { text: textOrDash(e.method) }),
      ])
    )
  );

  const table = el("table", { class: "engine-table" }, [thead, tbody]);
  const wrap = el("div", { class: "engine-table-wrap" }, [table]);

  return el("details", { class: "engines" }, [
    el("summary", { text: `Per-engine results (${engines.length})` }),
    wrap,
  ]);
}

/* ---------- panel renderers per type ---------- */

function typeLabel(kind) {
  return { ip: "IP ADDRESS", domain: "DOMAIN", url: "URL", file: "FILE HASH" }[kind] || kind.toUpperCase();
}

function buildPanel(kind, subject, data) {
  const title = el("h2", { class: "panel-title" }, [
    el("span", { text: `[ ${typeLabel(kind)} ]` }),
    el("span", { class: "subject", text: subject }),
  ]);

  const body = [
    buildStatGrid(data.stats),
    el("div", { class: "kv-grid" }, [
      kvRow("Reputation", data.reputation),
      kvRow("Last analysis", formatDate(data.last_analysis_date)),
    ]),
  ];

  // reputation color accent on the value we just added
  const repValueNode = body[1].querySelectorAll(".v")[0];
  if (repValueNode) repValueNode.classList.add(reputationClass(data.reputation));

  const typeSpecific = TYPE_SECTION_BUILDERS[kind](data);
  if (typeSpecific) body.push(typeSpecific);

  const tags = buildChips(data.tags);
  const categories = buildCategories(data.categories);
  if (tags || categories) {
    body.push(el("div", { class: "subhead", text: "Tags & categories" }));
    if (tags) body.push(tags);
    if (categories) body.push(categories);
  }

  const engineTable = buildEngineTable(data.engines);
  if (engineTable) body.push(engineTable);

  return el("section", { class: "panel" }, [title, ...body]);
}

function buildIpSection(data) {
  return el("div", { class: "kv-grid" }, [
    kvRow("Country", data.country),
    kvRow("Continent", data.continent),
    kvRow("ASN", data.asn),
    kvRow("AS Owner / ISP", data.as_owner),
    kvRow("Network (CIDR)", data.network),
    kvRow("Regional Internet Registry", data.regional_internet_registry),
  ]);
}

function buildDomainSection(data) {
  const wrap = document.createDocumentFragment();
  wrap.appendChild(
    el("div", { class: "kv-grid" }, [
      kvRow("Registrar", data.registrar),
      kvRow("Creation date", formatDate(data.creation_date)),
      kvRow("Last WHOIS update", formatDate(data.last_update_date)),
    ])
  );

  if (data.whois_summary) {
    wrap.appendChild(el("div", { class: "subhead", text: "WHOIS summary" }));
    wrap.appendChild(el("pre", { class: "raw-block", text: data.whois_summary }));
  }

  const dns = data.dns_records || {};
  const hasDns = Object.values(dns).some((arr) => arr && arr.length > 0);
  if (hasDns) {
    wrap.appendChild(el("div", { class: "subhead", text: "Last DNS records" }));
    const grid = el("div", { class: "kv-grid" });
    ["A", "MX", "NS", "TXT"].forEach((type) => {
      const values = dns[type] || [];
      if (values.length === 0) return;
      const list = el(
        "ul",
        { class: "dns-list" },
        values.map((v) => el("li", { text: v }))
      );
      grid.appendChild(
        el("div", { class: "kv-row" }, [el("span", { class: "k", text: type }), el("span", { class: "v" }, [list])])
      );
    });
    wrap.appendChild(grid);
  }

  const container = el("div");
  container.appendChild(wrap);
  return container;
}

function buildUrlSection(data) {
  return el("div", { class: "kv-grid" }, [
    kvRow("Final URL", data.final_url),
    kvRow("HTTP response code", data.http_response_code),
    kvRow("Page title", data.title),
  ]);
}

function buildFileSection(data) {
  return el("div", { class: "kv-grid" }, [
    kvRow("File type", data.type_description),
    kvRow("Size", formatBytes(data.size)),
    kvRow("Names seen", (data.names || []).join(", ") || null),
    kvRow("MD5", data.md5),
    kvRow("SHA-1", data.sha1),
    kvRow("SHA-256", data.sha256),
    kvRow("First submitted", formatDate(data.first_submission_date)),
    kvRow("Last submitted", formatDate(data.last_submission_date)),
  ]);
}

const TYPE_SECTION_BUILDERS = {
  ip: buildIpSection,
  domain: buildDomainSection,
  url: buildUrlSection,
  file: buildFileSection,
};

/* ---------- error rendering ---------- */

function showError(message) {
  const box = document.getElementById("error-box");
  box.textContent = message;
  box.hidden = false;
}

function clearError() {
  const box = document.getElementById("error-box");
  box.hidden = true;
  box.textContent = "";
}

/* ---------- main lookup flow ---------- */

async function performLookup(query) {
  const resultsEl = document.getElementById("results");
  const btn = document.getElementById("search-btn");

  clearError();
  resultsEl.innerHTML = "";

  const remainingMs = msUntilSlotFree();
  if (remainingMs > 0) {
    startThrottleCountdown();
    return;
  }

  requestTimestamps.push(Date.now());
  btn.disabled = true;
  btn.textContent = "SCANNING...";
  setStatus("querying VirusTotal...");

  try {
    const resp = await fetch("/api/lookup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query }),
    });

    let payload;
    try {
      payload = await resp.json();
    } catch (err) {
      throw new Error("Backend returned an unreadable response.");
    }

    if (!resp.ok) {
      throw new Error(payload && payload.error ? payload.error : `Request failed (${resp.status}).`);
    }

    setStatus(payload.cached ? "served from local cache" : "done");
    const panel = buildPanel(payload.type, payload.id, payload.data);
    resultsEl.appendChild(panel);
  } catch (err) {
    setStatus("");
    showError(err.message || "Something went wrong.");
  } finally {
    btn.disabled = false;
    btn.textContent = "SCAN";
  }
}

document.getElementById("search-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const input = document.getElementById("search-input");
  const query = input.value.trim();
  if (!query) return;
  performLookup(query);
});
