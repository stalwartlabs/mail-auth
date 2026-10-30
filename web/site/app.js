import init, {
  version,
  generate_key,
  inspect_key,
  sign_dkim1,
  sign_dkim2,
  sign_dkim2_revised,
  verify,
} from "./pkg/mail_auth_web.js";

const $ = (id) => document.getElementById(id);
const splitList = (value) =>
  value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

const STORE_KEY = "mailauth-playground";

const DEFAULT_DOMAIN = "example.com";

const sampleMessage = (domain) => `From: alice@${domain}
To: friends@${domain}
Subject: Hello from mail-auth
Date: Tue, 30 Jun 2026 10:00:00 +0000

Hi everyone,

This message was signed in the browser with mail-auth.

Cheers,
Alice
`;

const sampleModified = (domain) => `From: alice@${domain}
To: friends@${domain}
Subject: [friends] Hello from mail-auth
Date: Tue, 30 Jun 2026 10:00:00 +0000

Hi everyone,

This message was signed in the browser with mail-auth.

Cheers,
Alice
--
Sent via the friends@${domain} list
`;

const ALGORITHMS = {
  rsa: "RSA-SHA256",
  ed25519: "Ed25519-SHA256",
  "mldsa44": "MLDSA44",
};

const TXT_CHUNK = 255;

const state = {
  identity: null,
  dns: {
    mode: "live",
    endpoint: "https://cloudflare-dns.com/dns-query",
    format: "json",
    records: "",
    localKey: true,
  },
  hopMode: "smtp",
  gate: "verify",
  lastSigned: null,
};

function loadState() {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed.identity) state.identity = parsed.identity;
      if (parsed.dns) state.dns = { ...state.dns, ...parsed.dns };
    }
  } catch (_) {
    /* ignore corrupt storage */
  }
}

function saveState() {
  try {
    localStorage.setItem(
      STORE_KEY,
      JSON.stringify({ identity: state.identity, dns: state.dns })
    );
  } catch (_) {
    /* storage unavailable */
  }
}

function algoLabel(algorithm) {
  return ALGORITHMS[algorithm] || algorithm;
}

function activeDomain() {
  return (
    state.identity?.domain ||
    $("s-domain").value.trim() ||
    DEFAULT_DOMAIN
  );
}

function txtRecordLine(name, value) {
  const chunks = [];
  for (let i = 0; i < value.length; i += TXT_CHUNK) {
    chunks.push(`"${value.slice(i, i + TXT_CHUNK)}"`);
  }
  return `${name}. IN TXT ${chunks.join(" ")}`;
}

function dnsOpts() {
  const id = state.identity;
  const localRecords =
    state.dns.localKey && id && id.dnsName && id.dnsValue
      ? `${id.dnsName} TXT ${id.dnsValue}`
      : "";
  return {
    mode: state.dns.mode,
    dohEndpoint: state.dns.endpoint,
    dohFormat: state.dns.format,
    records: state.dns.records,
    localRecords,
  };
}

function dkim2Opts(id, mailFrom, rcptTo) {
  const flags = ["feedback", "feedhere", "exploded"].filter(
    (flag) => $(`d2-flag-${flag}`).checked
  );
  return {
    keyPem: id.pem,
    algorithm: id.algorithm,
    domain: id.domain,
    selector: id.selector,
    hashes: $("d2-hashes").value.split(","),
    flags,
    nonce: $("d2-nonce").value.trim(),
    hop: {
      kind: state.hopMode,
      mailFrom,
      rcptTo,
      nextDomain: $("d2-nd").value.trim(),
    },
    gate: state.gate,
    received: {
      mailFrom: $("d2-recv-mailfrom").value.trim(),
      rcptTo: splitList($("d2-recv-rcpt").value),
    },
    dns: dnsOpts(),
  };
}

function showTab(name) {
  document
    .querySelectorAll(".tab")
    .forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  document
    .querySelectorAll(".panel")
    .forEach((p) => (p.hidden = p.dataset.panel !== name));
  if (name !== "settings") refreshContextStrips();
}

function refreshContextStrips() {
  const signing = state.identity
    ? `Signing as <b>${state.identity.domain}</b> · "${state.identity.selector}" · ${algoLabel(
      state.identity.algorithm
    )}`
    : `No signing key yet; an Ed25519 key will be generated on first sign`;
  const dns =
    state.dns.mode === "offline"
      ? `DNS source <b>Manual records (offline)</b>`
      : `DNS source <b>Live · ${hostOf(state.dns.endpoint)}</b>`;

  document.querySelectorAll('[data-context="signing"]').forEach((el) => {
    el.innerHTML = `${signing}<a href="#" data-goto="settings">Settings</a>`;
  });
  document.querySelectorAll('[data-context="dns"]').forEach((el) => {
    el.innerHTML = `${dns}<a href="#" data-goto="settings">Settings</a>`;
  });
  $("d1-algo-note").hidden =
    state.identity?.algorithm !== "mldsa44";
}

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch (_) {
    return url;
  }
}

async function ensureKey() {
  if (state.identity) return state.identity;
  const domain = $("s-domain").value.trim() || DEFAULT_DOMAIN;
  const selector = $("s-selector").value.trim() || "default";
  const generated = generate_key("ed25519", 0, selector, domain);
  state.identity = {
    domain,
    selector,
    algorithm: generated.algorithm,
    pem: generated.private_pem,
    publicKey: generated.public_key,
    dnsName: generated.dns_record_name,
    dnsValue: generated.dns_record_value,
  };
  saveState();
  renderKeyStatus();
  refreshContextStrips();
  return state.identity;
}

function renderKeyStatus() {
  const status = $("s-key-status");
  if (!state.identity) {
    status.textContent = "No active key.";
    status.classList.remove("set");
    $("s-key-wrap").hidden = true;
    $("s-dns-wrap").hidden = true;
    return;
  }
  status.textContent = `Active key: ${algoLabel(state.identity.algorithm)} · ${state.identity.domain} · "${state.identity.selector}"`;
  status.classList.add("set");
  if (state.identity.pem) {
    $("s-key-pem").textContent = state.identity.pem;
    $("s-key-wrap").hidden = false;
  }
  if (state.identity.dnsName && state.identity.dnsValue) {
    $("s-dns-record").textContent = txtRecordLine(
      state.identity.dnsName,
      state.identity.dnsValue
    );
    $("s-dns-wrap").hidden = false;
  } else {
    $("s-dns-wrap").hidden = true;
  }
}

function showError(id, message) {
  const el = $(id);
  el.textContent = message;
  el.hidden = false;
}
function clearError(id) {
  $(id).hidden = true;
}
function showOutput(wrapId, preId, text) {
  $(preId).textContent = text;
  $(wrapId).hidden = false;
}
function showNote(id, text) {
  const el = $(id);
  el.textContent = text;
  el.hidden = !text;
}

function rememberSigned(message, mailFrom, rcptTo) {
  state.lastSigned =
    state.hopMode === "smtp" ? { message, mailFrom, rcptTo } : { message };
  $("v-last").disabled = false;
}

async function handleDkim1Sign() {
  clearError("d1-error");
  try {
    const id = await ensureKey();
    const out = sign_dkim1(
      id.pem,
      id.algorithm,
      id.domain,
      id.selector,
      splitList($("d1-headers").value),
      $("d1-message").value
    );
    showOutput("d1-output-wrap", "d1-output", out);
  } catch (err) {
    showError("d1-error", String(err));
  }
}

async function handleDkim2Sign() {
  clearError("d2-error");
  showNote("d2-validity", "");
  const btn = $("d2-sign");
  btn.disabled = true;
  try {
    const id = await ensureKey();
    const mailFrom = $("d2-mailfrom").value.trim();
    const rcptTo = splitList($("d2-rcpt").value);
    const result = await sign_dkim2(
      dkim2Opts(id, mailFrom, rcptTo),
      $("d2-message").value
    );
    showNote("d2-validity", result.validity);
    showOutput("d2-output-wrap", "d2-output", result.signed_message);
    $("d2-original").value = result.signed_message;
    if (state.hopMode === "smtp") {
      $("d2-recv-mailfrom").value = mailFrom;
      $("d2-recv-rcpt").value = rcptTo.join(", ");
    }
    rememberSigned(result.signed_message, mailFrom, rcptTo);
    updateReviseButton();
  } catch (err) {
    showError("d2-error", String(err));
  } finally {
    btn.disabled = false;
  }
}

async function handleDkim2Revise() {
  clearError("d2-rev-error");
  showNote("d2-rev-validity", "");
  const btn = $("d2-revise");
  btn.disabled = true;
  try {
    const id = await ensureKey();
    const mailFrom = $("d2-fwd-mailfrom").value.trim();
    const rcptTo = splitList($("d2-fwd-rcpt").value);
    const result = await sign_dkim2_revised(
      dkim2Opts(id, mailFrom, rcptTo),
      $("d2-original").value,
      $("d2-modified").value
    );
    showNote("d2-rev-validity", result.validity);
    showOutput(
      "d2-recipe-wrap",
      "d2-recipe",
      result.instance !== "null"
        ? result.instance
        : "The signed content matches the most recent Message-Instance, so no new instance was added; only a DKIM2-Signature was."
    );
    showOutput("d2-revout-wrap", "d2-revout", result.signed_message);
    rememberSigned(result.signed_message, mailFrom, rcptTo);
  } catch (err) {
    showError("d2-rev-error", String(err));
  } finally {
    updateReviseButton();
  }
}

function updateReviseButton() {
  const ready =
    $("d2-original").value.trim() !== "" && $("d2-modified").value.trim() !== "";
  $("d2-revise").disabled = !ready;
}

function chipClass(status) {
  if (status === "PASS") return "pass";
  if (status === "FAIL" || status === "PERMERROR") return "fail";
  if (status === "NONE") return "grey";
  return "warn";
}

function renderResults(res) {
  const order = [
    ["dkim", "DKIM"],
    ["dkim2", "DKIM2"],
    ["spf", "SPF"],
    ["dmarc", "DMARC"],
  ];
  const wrap = $("v-results");
  wrap.innerHTML = "";
  for (const [key, name] of order) {
    const r = res[key];
    if (!r) continue;
    const row = document.createElement("div");
    row.className = "result-row";
    row.innerHTML = `
      <div class="result-top">
        <span class="result-name">${name}</span>
        <span class="chip ${chipClass(r.status)}">${r.status}</span>
      </div>
      ${r.detail ? `<pre class="result-detail">${escapeHtml(r.detail)}</pre>` : ""}`;
    wrap.appendChild(row);
  }
  wrap.hidden = false;
}

function escapeHtml(s) {
  return s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

async function handleVerify() {
  clearError("v-error");
  const btn = $("v-run");
  btn.disabled = true;
  btn.textContent = "Verifying…";
  try {
    const res = await verify({
      dns: dnsOpts(),
      dkim2Mode: $("v-dkim2-mode").value,
      checkDkim: $("v-dkim").checked,
      checkDkim2: $("v-dkim2").checked,
      checkSpf: $("v-spf").checked,
      checkDmarc: $("v-dmarc").checked,
      remoteIp: $("v-ip").value,
      ehlo: $("v-ehlo").value,
      hostDomain: "",
      mailFrom: $("v-mailfrom").value,
      rcptTo: splitList($("v-rcpt").value),
      message: $("v-message").value,
    });
    renderResults(res);
  } catch (err) {
    showError("v-error", String(err));
  } finally {
    btn.disabled = false;
    btn.textContent = "Verify";
  }
}

function setupSettings() {
  document.querySelectorAll("#s-keymode .seg").forEach((seg) => {
    seg.addEventListener("click", () => {
      document
        .querySelectorAll("#s-keymode .seg")
        .forEach((s) => s.classList.toggle("active", s === seg));
      const mode = seg.dataset.keymode;
      document.querySelector('[data-keypane="paste"]').hidden = mode !== "paste";
      document.querySelector('[data-keypane="generate"]').hidden = mode !== "generate";
    });
  });

  $("s-use-key").addEventListener("click", () => {
    clearError("s-error");
    const pem = $("s-paste-key").value.trim();
    if (!pem) return showError("s-error", "Paste a PEM private key first.");
    try {
      const domain = $("s-domain").value.trim() || DEFAULT_DOMAIN;
      const selector = $("s-selector").value.trim() || "default";
      const k = inspect_key(pem, $("s-paste-algo").value, selector, domain);
      state.identity = {
        domain,
        selector,
        algorithm: k.algorithm,
        pem,
        publicKey: k.public_key,
        dnsName: k.dns_record_name,
        dnsValue: k.dns_record_value,
      };
      saveState();
      renderKeyStatus();
    } catch (err) {
      showError("s-error", String(err));
    }
  });

  $("s-generate").addEventListener("click", () => {
    clearError("s-error");
    try {
      const algo = $("s-gen-algo").value;
      const bits = parseInt($("s-gen-bits").value, 10) || 2048;
      const domain = $("s-domain").value.trim() || DEFAULT_DOMAIN;
      const selector = $("s-selector").value.trim() || "default";
      const g = generate_key(algo, bits, selector, domain);
      state.identity = {
        domain,
        selector,
        algorithm: g.algorithm,
        pem: g.private_pem,
        publicKey: g.public_key,
        dnsName: g.dns_record_name,
        dnsValue: g.dns_record_value,
      };
      saveState();
      renderKeyStatus();
    } catch (err) {
      showError("s-error", String(err));
    }
  });

  document.querySelectorAll("#s-dnsmode .seg").forEach((seg) => {
    seg.addEventListener("click", () => {
      document
        .querySelectorAll("#s-dnsmode .seg")
        .forEach((s) => s.classList.toggle("active", s === seg));
      const mode = seg.dataset.dnsmode;
      document.querySelector('[data-dnspane="live"]').hidden = mode !== "live";
      document.querySelector('[data-dnspane="offline"]').hidden = mode !== "offline";
      state.dns.mode = mode;
    });
  });

  const syncBits = () => {
    $("s-gen-bits-wrap").hidden = $("s-gen-algo").value !== "rsa";
  };
  $("s-gen-algo").addEventListener("change", syncBits);
  syncBits();

  $("s-doh-preset").addEventListener("change", (e) => {
    const v = e.target.value;
    if (v === "custom") return;
    const [endpoint, format] = v.split("|");
    $("s-doh-endpoint").value = endpoint;
    $("s-doh-format").value = format;
  });

  $("s-save-dns").addEventListener("click", () => {
    state.dns = {
      mode: document.querySelector("#s-dnsmode .seg.active").dataset.dnsmode,
      endpoint: $("s-doh-endpoint").value.trim(),
      format: $("s-doh-format").value,
      records: $("s-records").value,
      localKey: $("s-local-key").checked,
    };
    saveState();
    const flash = $("s-dns-saved");
    flash.hidden = false;
    setTimeout(() => (flash.hidden = true), 1500);
  });
}

function setupSegmented(selector, key, paneKey, onChange) {
  const segs = document.querySelectorAll(`${selector} .seg`);
  segs.forEach((seg) => {
    seg.addEventListener("click", () => {
      segs.forEach((s) => s.classList.toggle("active", s === seg));
      const value = seg.dataset[key];
      document
        .querySelectorAll(`[data-${paneKey}]`)
        .forEach((pane) => (pane.hidden = pane.dataset[paneKey] !== value));
      onChange(value);
    });
  });
}

function hydrateSettingsInputs() {
  if (state.identity) {
    $("s-domain").value = state.identity.domain;
    $("s-selector").value = state.identity.selector;
  }
  $("s-doh-endpoint").value = state.dns.endpoint;
  $("s-doh-format").value = state.dns.format;
  $("s-records").value = state.dns.records;
  $("s-local-key").checked = state.dns.localKey !== false;
  if (state.dns.mode === "offline") {
    document.querySelector('#s-dnsmode .seg[data-dnsmode="offline"]').click();
  }
}

function setupGenericButtons() {
  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const text = $(btn.dataset.copy).textContent;
      try {
        await navigator.clipboard.writeText(text);
        const old = btn.textContent;
        btn.textContent = "Copied";
        setTimeout(() => (btn.textContent = old), 1200);
      } catch (_) {
        /* clipboard blocked */
      }
    });
  });

  document.querySelectorAll("[data-sample]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const kind = btn.dataset.sample;
      const domain = activeDomain();
      if (kind === "d2-message") {
        $("d2-message").value = sampleMessage(domain);
        $("d2-mailfrom").value = `alice@${domain}`;
        $("d2-rcpt").value = `friends@${domain}`;
      } else if (kind === "d1-message") $("d1-message").value = sampleMessage(domain);
      else if (kind === "v-message") $("v-message").value = sampleMessage(domain);
      else if (kind === "d2-revised") {
        const signed = state.lastSigned?.message;
        $("d2-original").value = signed || sampleMessage(domain);
        $("d2-modified").value = signed
          ? signed.replace(
            /^Subject: Hello from mail-auth/m,
            "Subject: [friends] Hello from mail-auth"
          ) + `--\r\nSent via the friends@${domain} list\r\n`
          : sampleModified(domain);
        $("d2-fwd-mailfrom").value = `friends-bounces@${domain}`;
        $("d2-fwd-rcpt").value = "bob@example.net, carol@example.org";
      }
      updateReviseButton();
    });
  });

  document.getElementById("tabs").addEventListener("click", (e) => {
    const tab = e.target.closest(".tab");
    if (tab) showTab(tab.dataset.tab);
  });

  document.body.addEventListener("click", (e) => {
    const goto = e.target.closest("[data-goto]");
    if (goto) {
      e.preventDefault();
      showTab(goto.dataset.goto);
    }
  });

  $("d2-copy-orig").addEventListener("click", () => {
    $("d2-modified").value = $("d2-original").value;
    updateReviseButton();
  });

  $("d2-original").addEventListener("input", updateReviseButton);
  $("d2-modified").addEventListener("input", updateReviseButton);

  setupSegmented("#d2-hopmode", "hopmode", "hoppane", (mode) => {
    state.hopMode = mode;
  });
  setupSegmented("#d2-gate", "gate", "gatepane", (gate) => {
    state.gate = gate;
  });

  $("v-last").addEventListener("click", () => {
    const last = state.lastSigned;
    if (!last) return;
    $("v-message").value = last.message;
    if (last.mailFrom !== undefined) {
      $("v-mailfrom").value = last.mailFrom;
      $("v-rcpt").value = last.rcptTo.join(", ");
    }
  });

  $("d1-sign").addEventListener("click", handleDkim1Sign);
  $("d2-sign").addEventListener("click", handleDkim2Sign);
  $("d2-revise").addEventListener("click", handleDkim2Revise);
  $("v-run").addEventListener("click", handleVerify);
}

async function boot() {
  const badge = $("wasm-badge");
  try {
    await init();
    badge.textContent = `mail-auth v${version()}`;
    badge.dataset.state = "ok";
  } catch (err) {
    badge.textContent = "wasm failed";
    badge.dataset.state = "err";
    console.error(err);
    return;
  }

  loadState();
  setupSettings();
  setupGenericButtons();
  hydrateSettingsInputs();
  renderKeyStatus();

  const domain = activeDomain();
  $("d2-message").value = sampleMessage(domain);
  $("d1-message").value = sampleMessage(domain);
  if (domain !== DEFAULT_DOMAIN) {
    $("d2-mailfrom").value = `alice@${domain}`;
    $("d2-rcpt").value = `friends@${domain}`;
    $("d2-recv-mailfrom").value = `alice@${domain}`;
    $("d2-recv-rcpt").value = `friends@${domain}`;
    $("d2-fwd-mailfrom").value = `friends-bounces@${domain}`;
    $("v-mailfrom").value = `alice@${domain}`;
    $("v-rcpt").value = `friends@${domain}`;
  }
  updateReviseButton();

  showTab("dkim2");
}

boot();
