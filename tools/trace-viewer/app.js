const sampleTrace = {
  module: {
    name: "audit_plugin",
    functions: [
      {
        name: "main",
        source_lines: [16, 17, 18, 19, 20, 21, 23, 26, 27, 28, 26, 31, 32],
      },
    ],
  },
  entry: "main",
  checksum: "14837601390650843185",
  result: { Array: [{ String: "review" }, { I64: 1900000000 }, { I64: 424242 }, { I64: 5 }] },
  error: null,
  source: {
    16: "let timestamp = cap clock.now@1()",
    17: "let request = cap random.u64@1()",
    18: "let amount = 640",
    19: "let attempts = 3",
    20: "let risk = risk_points(amount, attempts)",
    21: "let approved = risk <= 4",
    23: "print(\"audit start\", timestamp, request)",
    26: "while step < 3",
    27: "print(\"check\", step, \"risk\", risk)",
    28: "let step = step + 1",
    31: "print(\"decision\", \"review\", amount)",
    32: "return [\"review\", timestamp, request, risk]",
  },
  events: [
    {
      function: "main",
      pc: 0,
      opcode: "cap_call",
      source_line: 16,
      register_changes: [{ register: 0, value: { I64: 1900000000 } }],
      capability: {
        id: "clock.now@1",
        decision: "mocked",
        args: [],
        result: { I64: 1900000000 },
      },
      error: null,
      checksum: "10596808881269225500",
    },
    {
      function: "main",
      pc: 1,
      opcode: "cap_call",
      source_line: 17,
      register_changes: [{ register: 1, value: { I64: 424242 } }],
      capability: {
        id: "random.u64@1",
        decision: "mocked",
        args: [],
        result: { I64: 424242 },
      },
      error: null,
      checksum: "11290358912882555221",
    },
    {
      function: "main",
      pc: 6,
      opcode: "cap_call",
      source_line: 23,
      register_changes: [{ register: 12, value: "Nil" }],
      capability: {
        id: "log.print@1",
        decision: "granted",
        args: [{ String: "audit start" }, { I64: 1900000000 }, { I64: 424242 }],
        result: "Nil",
      },
      error: null,
      checksum: "6941072857733409014",
    },
    {
      function: "main",
      pc: 12,
      opcode: "cap_call",
      source_line: 31,
      register_changes: [{ register: 28, value: "Nil" }],
      capability: {
        id: "log.print@1",
        decision: "granted",
        args: [{ String: "decision" }, { String: "review" }, { I64: 640 }],
        result: "Nil",
      },
      error: null,
      checksum: "10173148359687722360",
    },
  ],
};

let trace = sampleTrace;
let selectedIndex = 0;
let activeTab = "registers";
let filterText = "";

const elements = {
  fileInput: document.querySelector("#fileInput"),
  loadSample: document.querySelector("#loadSample"),
  exportSummary: document.querySelector("#exportSummary"),
  dropzone: document.querySelector("#dropzone"),
  moduleName: document.querySelector("#moduleName"),
  entryName: document.querySelector("#entryName"),
  eventCount: document.querySelector("#eventCount"),
  traceChecksum: document.querySelector("#traceChecksum"),
  checksumStatus: document.querySelector("#checksumStatus"),
  timeline: document.querySelector("#timeline"),
  filterInput: document.querySelector("#filterInput"),
  prevEvent: document.querySelector("#prevEvent"),
  nextEvent: document.querySelector("#nextEvent"),
  eventPosition: document.querySelector("#eventPosition"),
  eventOpcode: document.querySelector("#eventOpcode"),
  eventChecksum: document.querySelector("#eventChecksum"),
  eventFunction: document.querySelector("#eventFunction"),
  eventPc: document.querySelector("#eventPc"),
  eventLine: document.querySelector("#eventLine"),
  capabilityDetail: document.querySelector("#capabilityDetail"),
  registerChanges: document.querySelector("#registerChanges"),
  capabilityAudit: document.querySelector("#capabilityAudit"),
  sourceMap: document.querySelector("#sourceMap"),
  rawEvent: document.querySelector("#rawEvent"),
};

function render() {
  if (!trace || !Array.isArray(trace.events)) {
    return;
  }
  selectedIndex = clamp(selectedIndex, 0, trace.events.length - 1);
  renderSummary();
  renderTimeline();
  renderDetail();
  renderTabs();
}

function renderSummary() {
  elements.moduleName.textContent = trace.module?.name ?? "-";
  elements.entryName.textContent = trace.entry ?? "-";
  elements.eventCount.textContent = trace.events.length.toString();
  elements.traceChecksum.textContent = trace.checksum ?? "-";
  const checksummedEvents = trace.events.filter((event) => event.checksum !== undefined && event.checksum !== null).length;
  elements.checksumStatus.textContent = trace.error
    ? "captured error"
    : `${checksummedEvents}/${trace.events.length} event checksums`;
}

function renderTimeline() {
  const rows = trace.events
    .map((event, index) => ({ event, index }))
    .filter(({ event }) => matchesFilter(event));

  elements.timeline.replaceChildren(
    ...rows.map(({ event, index }) => {
      const item = document.createElement("li");
      const button = document.createElement("button");
      button.type = "button";
      button.className = index === selectedIndex ? "active" : "";
      button.innerHTML = `
        <span class="timeline-meta">#${index} ${event.function} pc=${event.pc} line=${event.source_line ?? "-"}</span>
        <span class="timeline-op">${event.opcode}${event.capability ? ` · ${event.capability.id}` : ""}</span>
      `;
      button.addEventListener("click", () => {
        selectedIndex = index;
        render();
      });
      item.append(button);
      return item;
    }),
  );
}

function renderDetail() {
  const event = trace.events[selectedIndex];
  if (!event) {
    return;
  }
  elements.eventPosition.textContent = `Event ${selectedIndex} of ${trace.events.length - 1}`;
  elements.eventOpcode.textContent = event.opcode;
  elements.eventChecksum.textContent = event.checksum ?? "-";
  elements.eventFunction.textContent = event.function ?? "-";
  elements.eventPc.textContent = event.pc ?? "-";
  elements.eventLine.textContent = event.source_line ?? "-";
  renderCapability(event.capability);
  renderRegisterChanges(event.register_changes ?? []);
  renderAudit();
  renderSourceMap();
  elements.rawEvent.textContent = JSON.stringify(event, null, 2);
}

function renderCapability(capability) {
  if (!capability) {
    elements.capabilityDetail.className = "empty-state";
    elements.capabilityDetail.textContent = "No capability call on this event.";
    return;
  }
  elements.capabilityDetail.className = "";
  elements.capabilityDetail.innerHTML = `
    <div class="cap-line"><span>ID</span><strong>${escapeHtml(capability.id)}</strong></div>
    <div class="cap-line"><span>Decision</span><strong>${escapeHtml(capability.decision)}</strong></div>
    <div class="cap-line"><span>Args</span><strong>${capability.args.map(formatValue).join(", ") || "-"}</strong></div>
    <div class="cap-line"><span>Result</span><strong>${formatValue(capability.result)}</strong></div>
  `;
}

function renderRegisterChanges(changes) {
  if (!changes.length) {
    elements.registerChanges.innerHTML = `<div class="empty-state">No register changes.</div>`;
    return;
  }
  elements.registerChanges.replaceChildren(
    ...changes.map((change) => {
      const row = document.createElement("div");
      row.className = "kv-row";
      row.innerHTML = `<span>r${change.register}</span><strong>${formatValue(change.value)}</strong>`;
      return row;
    }),
  );
}

function renderAudit() {
  const calls = new Map();
  const callRows = [];
  for (const event of trace.events) {
    if (!event.capability) continue;
    const current = calls.get(event.capability.id) ?? { total: 0, granted: 0, mocked: 0 };
    current.total += 1;
    if (event.capability.decision === "Granted" || event.capability.decision === "granted") {
      current.granted += 1;
    }
    if (event.capability.decision === "Mocked" || event.capability.decision === "mocked") {
      current.mocked += 1;
    }
    calls.set(event.capability.id, current);
    callRows.push({ event, capability: event.capability, index: trace.events.indexOf(event) });
  }
  if (!calls.size) {
    elements.capabilityAudit.innerHTML = `<div class="empty-state">No capability calls recorded.</div>`;
    return;
  }
  const summaryRows = Array.from(calls.entries()).map(([id, value]) => {
      const row = document.createElement("div");
      row.className = "audit-row";
      row.innerHTML = `<span>${escapeHtml(id)}</span><strong>${value.total} calls · ${value.granted} granted · ${value.mocked} mocked</strong>`;
      return row;
  });
  const timeline = document.createElement("div");
  timeline.className = "cap-timeline";
  timeline.append(
    ...callRows.map(({ event, capability, index }) => {
      const button = document.createElement("button");
      button.type = "button";
      button.innerHTML = `<span>#${index} line ${event.source_line ?? "-"}</span><strong>${escapeHtml(capability.id)} · ${escapeHtml(capability.decision)}</strong>`;
      button.addEventListener("click", () => {
        selectedIndex = index;
        activeTab = "registers";
        render();
      });
      return button;
    }),
  );
  elements.capabilityAudit.replaceChildren(...summaryRows, timeline);
}

function renderSourceMap() {
  const rows = trace.events.map((event, index) => ({ event, index }));
  if (!rows.length) {
    elements.sourceMap.innerHTML = `<div class="empty-state">No source line data recorded.</div>`;
    return;
  }
  elements.sourceMap.replaceChildren(
    ...rows.map(({ event, index }) => {
      const row = document.createElement("button");
      row.type = "button";
      row.className = index === selectedIndex ? "source-row active" : "source-row";
      const sourceText = sourceForEvent(event);
      row.innerHTML = `
        <span>#${index} ${escapeHtml(event.function)} pc=${event.pc} line=${event.source_line ?? "-"}</span>
        <strong>${escapeHtml(sourceText)}</strong>
        <em>${escapeHtml(event.opcode)}${event.capability ? ` · ${event.capability.id}` : ""}</em>
      `;
      row.addEventListener("click", () => {
        selectedIndex = index;
        render();
      });
      return row;
    }),
  );
}

function renderTabs() {
  for (const button of document.querySelectorAll(".tab")) {
    button.classList.toggle("active", button.dataset.tab === activeTab);
  }
  document.querySelector("#registersTab").classList.toggle("active", activeTab === "registers");
  document.querySelector("#auditTab").classList.toggle("active", activeTab === "audit");
  document.querySelector("#sourceTab").classList.toggle("active", activeTab === "source");
  document.querySelector("#rawTab").classList.toggle("active", activeTab === "raw");
}

function sourceForEvent(event) {
  if (trace.source && event.source_line != null && trace.source[event.source_line]) {
    return trace.source[event.source_line];
  }
  const fn = trace.module?.functions?.find((item) => item.name === event.function);
  if (fn?.source_lines?.[event.pc] != null) {
    return `source line ${fn.source_lines[event.pc]}`;
  }
  return event.source_line == null ? "source line unavailable" : `source line ${event.source_line}`;
}

function exportSummary() {
  const capCounts = {};
  for (const event of trace.events) {
    if (!event.capability) continue;
    capCounts[event.capability.id] ??= { calls: 0, granted: 0, mocked: 0, replayed: 0 };
    capCounts[event.capability.id].calls += 1;
    capCounts[event.capability.id][String(event.capability.decision).toLowerCase()] += 1;
  }
  const summary = {
    module: trace.module?.name,
    entry: trace.entry,
    events: trace.events.length,
    checksum: trace.checksum,
    result: trace.result,
    error: trace.error,
    capabilities: capCounts,
  };
  const blob = new Blob([JSON.stringify(summary, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `${trace.module?.name ?? "chronicle"}-summary.json`;
  link.click();
  URL.revokeObjectURL(url);
}

function matchesFilter(event) {
  if (!filterText) return true;
  const haystack = [
    event.function,
    event.pc,
    event.source_line,
    event.opcode,
    event.checksum,
    event.capability?.id,
    event.capability?.decision,
  ]
    .join(" ")
    .toLowerCase();
  return haystack.includes(filterText.toLowerCase());
}

async function loadFile(file) {
  const text = await file.text();
  const parsed = parseTraceJson(text);
  if (!Array.isArray(parsed.events)) {
    throw new Error("Trace JSON must contain an events array.");
  }
  trace = parsed;
  selectedIndex = 0;
  render();
}

function parseTraceJson(text) {
  const checksumSafeText = text.replace(/("checksum"\\s*:\\s*)(\\d{16,})/g, '$1"$2"');
  return JSON.parse(checksumSafeText);
}

function formatValue(value) {
  if (value === null || value === undefined) return "nil";
  if (typeof value === "string") return value === "Nil" ? "nil" : escapeHtml(value);
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return `[${value.map(formatValue).join(", ")}]`;
  if (typeof value === "object") {
    const [kind, inner] = Object.entries(value)[0] ?? ["Object", value];
    if (kind === "Array" && Array.isArray(inner)) return `[${inner.map(formatValue).join(", ")}]`;
    if (kind === "String") return escapeHtml(inner);
    if (kind === "I64" || kind === "F64" || kind === "Bool") return String(inner);
    if (kind === "Nil") return "nil";
    return `${kind}(${Array.isArray(inner) ? inner.map(formatValue).join(", ") : formatValue(inner)})`;
  }
  return escapeHtml(String(value));
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

elements.fileInput.addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  try {
    await loadFile(file);
  } catch (error) {
    alert(error.message);
  }
});

elements.loadSample.addEventListener("click", () => {
  trace = sampleTrace;
  selectedIndex = 0;
  render();
});

elements.exportSummary.addEventListener("click", exportSummary);

elements.prevEvent.addEventListener("click", () => {
  selectedIndex = clamp(selectedIndex - 1, 0, trace.events.length - 1);
  render();
});

elements.nextEvent.addEventListener("click", () => {
  selectedIndex = clamp(selectedIndex + 1, 0, trace.events.length - 1);
  render();
});

elements.filterInput.addEventListener("input", (event) => {
  filterText = event.target.value;
  renderTimeline();
});

for (const button of document.querySelectorAll(".tab")) {
  button.addEventListener("click", () => {
    activeTab = button.dataset.tab;
    renderTabs();
  });
}

for (const eventName of ["dragenter", "dragover"]) {
  elements.dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    elements.dropzone.classList.add("dragging");
  });
}

for (const eventName of ["dragleave", "drop"]) {
  elements.dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    elements.dropzone.classList.remove("dragging");
  });
}

elements.dropzone.addEventListener("drop", async (event) => {
  const file = event.dataTransfer?.files?.[0];
  if (!file) return;
  try {
    await loadFile(file);
  } catch (error) {
    alert(error.message);
  }
});

render();
