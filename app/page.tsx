"use client";

import {
  ArrowDownToLine,
  ArrowRightLeft,
  Braces,
  Check,
  ChevronDown,
  CircleHelp,
  Clipboard,
  Clock3,
  Code2,
  FileCode2,
  FileInput,
  FileOutput,
  Gauge,
  Globe2,
  Inbox,
  Layers3,
  ListChecks,
  LockKeyhole,
  Mail,
  Network,
  Plus,
  RotateCcw,
  Search,
  Settings2,
  ShieldCheck,
  Sparkles,
  StickyNote,
  Trash2,
  Upload,
  UserRound,
  X
} from "lucide-react";
import { ChangeEvent, useEffect, useMemo, useState } from "react";
import {
  analyzeEmail,
  AuditItem,
  formatBytes,
  makeContactMatrix
} from "@/lib/email-engine";

const sampleEmail = `Received: from relay-03.mailhost.net ([203.0.113.42]) by mx.google.com with ESMTPS id abc123; Mon, 2 Nov 2026 10:42:18 -0800
Return-Path: <bounce@campaign.example>
Delivered-To: recipient@gmail.com
Authentication-Results: mx.google.com; dkim=pass; spf=pass
From: "Alex from Northstar" <hello@northstar.example>
To: Jamie Rivera <jamie.rivera@gmail.com>
Reply-To: support@northstar.example
Subject: Your November field notes are here
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<!doctype html>
<html><body>
  <p>Hi Jamie,</p>
  <p>Here's your update from Northstar. Visit https://northstar.example/november?email=jamie.rivera@gmail.com</p>
  <p>Questions? Write to hello@northstar.example.</p>
</body></html>`;

type Tab = "sanitizer" | "ledger";
type Note = { id: number; title: string; body: string; done: boolean };
type LedgerSnapshot = {
  notes: Note[];
  checklist: boolean[];
  usernameOne: string;
  usernameTwo: string;
  domainsInput: string;
};

function isLedgerSnapshot(value: unknown): value is LedgerSnapshot {
  if (!value || typeof value !== "object") return false;
  const snapshot = value as Partial<LedgerSnapshot>;
  return Array.isArray(snapshot.notes)
    && snapshot.notes.every((note) =>
      typeof note.id === "number"
      && typeof note.title === "string"
      && typeof note.body === "string"
      && typeof note.done === "boolean"
    )
    && Array.isArray(snapshot.checklist)
    && snapshot.checklist.length === 4
    && snapshot.checklist.every((item) => typeof item === "boolean")
    && typeof snapshot.usernameOne === "string"
    && typeof snapshot.usernameTwo === "string"
    && typeof snapshot.domainsInput === "string";
}

const initialNotes: Note[] = [
  { id: 1, title: "Warm-up pool", body: "Ramp new IPs gradually. Review complaint rate after each volume step.", done: true },
  { id: 2, title: "Northstar · SPF", body: "Confirm include chain is under the 10-DNS-lookup limit before launch.", done: false },
  { id: 3, title: "Bounce domain", body: "Verify MX and custom return-path alignment in the staging workspace.", done: false }
];

function AuditRow({ item }: { item: AuditItem }) {
  const icon = item.category === "routing" ? Network : item.category === "authentication" ? ShieldCheck : Clock3;
  const Icon = icon;

  return (
    <div className="audit-row">
      <div className={`audit-icon ${item.category}`}><Icon size={14} /></div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center justify-between gap-3">
          <span className="audit-name">{item.name}</span>
          <span className="audit-category">{item.category}</span>
        </div>
        <p className="audit-value" title={item.value}>{item.value}</p>
      </div>
    </div>
  );
}

export default function Home() {
  const [activeTab, setActiveTab] = useState<Tab>("sanitizer");
  const [raw, setRaw] = useState(sampleEmail);
  const [notes, setNotes] = useState(initialNotes);
  const [checklist, setChecklist] = useState([true, true, false, false]);
  const [activeOutput, setActiveOutput] = useState<"template" | "audit">("template");
  const [copied, setCopied] = useState(false);
  const [search, setSearch] = useState("");
  const [usernameOne, setUsernameOne] = useState("alex");
  const [usernameTwo, setUsernameTwo] = useState("jordan");
  const [domainsInput, setDomainsInput] = useState("northstar.example\nnorthstar.co\ntry-northstar.com\nnorthstar-mail.net");
  const [newNoteTitle, setNewNoteTitle] = useState("");
  const [newNoteBody, setNewNoteBody] = useState("");
  const [showNoteForm, setShowNoteForm] = useState(false);
  const [ledgerLoaded, setLedgerLoaded] = useState(false);
  const [ledgerStorageError, setLedgerStorageError] = useState(false);
  const analysis = useMemo(() => analyzeEmail(raw), [raw]);
  const domains = domainsInput.split(/\n|,/).map((value) => value.trim()).filter(Boolean).slice(0, 4);
  const contacts = makeContactMatrix([usernameOne, usernameTwo].filter(Boolean), domains);
  const filteredAudit = analysis.audit.filter((item) =>
    `${item.name} ${item.value}`.toLowerCase().includes(search.toLowerCase())
  );

  useEffect(() => {
    try {
      const saved = window.localStorage.getItem("mailroom-ledger-v1");
      if (saved) {
        const parsed: unknown = JSON.parse(saved);
        if (!isLedgerSnapshot(parsed)) {
          setLedgerStorageError(true);
        } else {
          setNotes(parsed.notes);
          setChecklist(parsed.checklist);
          setUsernameOne(parsed.usernameOne);
          setUsernameTwo(parsed.usernameTwo);
          setDomainsInput(parsed.domainsInput);
        }
      }
    } catch {
      setLedgerStorageError(true);
    } finally {
      setLedgerLoaded(true);
    }
  }, []);

  useEffect(() => {
    if (!ledgerLoaded) return;
    try {
      const snapshot: LedgerSnapshot = { notes, checklist, usernameOne, usernameTwo, domainsInput };
      window.localStorage.setItem("mailroom-ledger-v1", JSON.stringify(snapshot));
      setLedgerStorageError(false);
    } catch {
      setLedgerStorageError(true);
    }
  }, [ledgerLoaded, notes, checklist, usernameOne, usernameTwo, domainsInput]);

  const copyOutput = async () => {
    await navigator.clipboard.writeText(analysis.cleanedTemplate);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  };

  const uploadSource = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setRaw(await file.text());
    event.target.value = "";
  };

  const addNote = () => {
    if (!newNoteTitle.trim()) return;
    setNotes((current) => [
      { id: Date.now(), title: newNoteTitle.trim(), body: newNoteBody.trim(), done: false },
      ...current
    ]);
    setNewNoteTitle("");
    setNewNoteBody("");
    setShowNoteForm(false);
  };

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#" aria-label="Mailroom home">
          <span className="brand-mark"><Mail size={18} strokeWidth={2.2} /></span>
          <span className="brand-name">mailroom<span>.</span></span>
        </a>
        <div className="workspace-switcher">
          <div className="workspace-avatar">N</div>
          <div className="workspace-copy"><strong>Northstar Labs</strong><span>Deliverability team</span></div>
          <ChevronDown size={15} className="muted" />
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav className="main-nav" aria-label="Workspace navigation">
          <button className={`nav-item ${activeTab === "sanitizer" ? "active" : ""}`} onClick={() => setActiveTab("sanitizer")}>
            <ArrowRightLeft size={17} /> <span>Template lab</span><span className="nav-shortcut">⌘ 1</span>
          </button>
          <button className={`nav-item ${activeTab === "ledger" ? "active" : ""}`} onClick={() => setActiveTab("ledger")}>
            <Layers3 size={17} /> <span>Infrastructure ledger</span>
          </button>
        </nav>
        <div className="nav-label nav-label-spaced">TOOLS</div>
        <nav className="main-nav" aria-label="Utilities">
          <button className="nav-item" onClick={() => setActiveTab("ledger")}><Globe2 size={17} /><span>Domain checks</span><span className="nav-dot" /></button>
          <button className="nav-item" onClick={() => setActiveTab("ledger")}><ListChecks size={17} /><span>Contact matrix</span></button>
        </nav>
        <div className="sidebar-bottom">
          <div className="plan-card">
            <div className="plan-icon"><Gauge size={16} /></div>
            <div><strong>Local workspace</strong><span>Your data stays in this browser</span></div>
            <LockKeyhole size={13} className="muted" />
          </div>
          <button className="profile-button"><div className="profile-avatar">AR</div><span className="profile-name">Alex Rivera<small>Mail ops</small></span><Settings2 size={16} className="muted" /></button>
        </div>
      </aside>

      <section className="main-area">
        <header className="topbar">
          <div className="breadcrumbs"><span>Workspace</span><span className="crumb-slash">/</span><strong>{activeTab === "sanitizer" ? "Template lab" : "Infrastructure ledger"}</strong></div>
          <div className="topbar-right">
            <span className="status-pill"><span /> All systems operational</span>
            <button className="icon-button" aria-label="Help"><CircleHelp size={17} /></button>
            <div className="top-avatar">AR</div>
          </div>
        </header>

        {activeTab === "sanitizer" ? (
          <div className="page-content">
            <div className="page-heading">
              <div>
                <div className="eyebrow"><span className="eyebrow-dot" /> DELIVERABILITY TOOLKIT <span className="eyebrow-separator">/</span> 01</div>
                <h1>Template lab</h1>
                <p>Strip transport noise. Recover the template underneath.</p>
              </div>
              <div className="heading-actions">
                <button className="button button-quiet" onClick={() => setRaw("")}><RotateCcw size={15} /> Reset</button>
                <label className="button button-primary upload-button"><Upload size={15} /> Import source<input type="file" accept=".eml,.txt,.email,text/plain,message/rfc822" onChange={uploadSource} /></label>
              </div>
            </div>

            <div className="stat-strip">
              <div className="stat-card"><div className="stat-icon blue"><FileInput size={16} /></div><div className="stat-copy"><span>Source size</span><strong>{formatBytes(new TextEncoder().encode(raw).length)}</strong></div></div>
              <div className="stat-card"><div className="stat-icon orange"><Layers3 size={16} /></div><div className="stat-copy"><span>Headers parsed</span><strong>{analysis.headerCount.toString().padStart(2, "0")}</strong></div></div>
              <div className="stat-card"><div className="stat-icon violet"><Braces size={16} /></div><div className="stat-copy"><span>Tags detected</span><strong>{analysis.detectedTags.length.toString().padStart(2, "0")}</strong></div></div>
              <div className="stat-card"><div className="stat-icon green"><ShieldCheck size={16} /></div><div className="stat-copy"><span>Transport stripped</span><strong>{analysis.audit.length.toString().padStart(2, "0")} <small>headers</small></strong></div></div>
              <div className="live-indicator"><span className="pulse-dot" /> LIVE</div>
            </div>

            <div className="workbench">
              <section className="panel input-panel">
                <div className="panel-header">
                  <div className="panel-title-group"><div className="panel-icon input"><Code2 size={16} /></div><div><h2>Raw source</h2><p>Paste a fully sent RFC 5322 message</p></div></div>
                  <span className="panel-kicker">INPUT <span>01</span></span>
                </div>
                <div className="editor-wrap">
                  <div className="editor-gutter">{raw.split("\n").map((_, index) => <span key={index}>{String(index + 1).padStart(2, "0")}</span>)}</div>
                  <textarea className="source-editor" aria-label="Raw email source" spellCheck={false} value={raw} onChange={(event) => setRaw(event.target.value)} placeholder="Paste raw email source here..." />
                </div>
                <div className="input-footer"><span><span className="footer-dot" /> RFC 5322 PARSER READY</span><button className="text-button" onClick={() => setRaw(sampleEmail)}><Sparkles size={13} /> Load sample</button></div>
              </section>

              <section className="panel output-panel">
                <div className="panel-header output-heading">
                  <div className="panel-title-group"><div className="panel-icon output"><FileOutput size={16} /></div><div><h2>Recovered template</h2><p>Clean headers with reverse-tag mapping</p></div></div>
                  <div className="output-actions"><span className="ready-badge"><span /> READY</span><button className="icon-button small" aria-label="Download output" onClick={() => {
                    const blob = new Blob([analysis.cleanedTemplate], { type: "text/plain;charset=utf-8" });
                    const url = URL.createObjectURL(blob);
                    const link = document.createElement("a");
                    link.href = url;
                    link.download = "recovered-template.eml";
                    link.click();
                    URL.revokeObjectURL(url);
                  }}><ArrowDownToLine size={15} /></button><button className="button button-copy" onClick={copyOutput}>{copied ? <Check size={14} /> : <Clipboard size={14} />}{copied ? "Copied" : "Copy"}</button></div>
                </div>
                <div className="output-tabs">
                  <button className={activeOutput === "template" ? "selected" : ""} onClick={() => setActiveOutput("template")}><FileCode2 size={14} /> Template <span>{formatBytes(new TextEncoder().encode(analysis.cleanedTemplate).length)}</span></button>
                  <button className={activeOutput === "audit" ? "selected" : ""} onClick={() => setActiveOutput("audit")}><Layers3 size={14} /> Stripped elements <span className="tab-count">{analysis.audit.length}</span></button>
                </div>
                {activeOutput === "template" ? (
                  <div className="output-code-wrap">
                    <div className="output-code">
                      {analysis.cleanedTemplate ? (
                        analysis.cleanedTemplate.split("\n").map((line, index) => (
                          <div className="code-line" key={`${index}-${line.slice(0, 20)}`}><span className="line-number">{String(index + 1).padStart(2, "0")}</span><code>{line.split(/(__[A-Za-z][A-Za-z0-9]*(?:\[[^\]]*\]|\([^)]*\))?|user_dom)/g).map((part, partIndex) => /^(__|user_dom)/.test(part) ? <span className="tag-token" key={partIndex}>{part}</span> : <span key={partIndex}>{part || "\u00a0"}</span>)}</code></div>
                        ))
                      ) : <div className="empty-editor"><FileInput size={24} /><span>Paste a message source to get started</span></div>}
                    </div>
                    <div className="output-code-footer"><span><Braces size={13} /> {analysis.replacements.length} value mappings applied</span><span>UTF-8 · LF</span></div>
                  </div>
                ) : (
                  <div className="audit-view">
                    <div className="audit-toolbar"><div><strong>{analysis.audit.length} extracted headers</strong><span> Removed from the recovered template</span></div><div className="search-box"><Search size={14} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Filter headers" aria-label="Filter audit headers" /></div></div>
                    <div className="audit-list">
                      {filteredAudit.length ? filteredAudit.map((item, index) => <AuditRow item={item} key={`${item.name}-${index}`} />) : <div className="audit-empty">{analysis.audit.length ? "No headers match your filter." : "No transport headers found in this source."}</div>}
                    </div>
                    <div className="audit-note"><ShieldCheck size={14} /><span>Transport metadata is preserved here for review and never sent to a server.</span></div>
                  </div>
                )}
              </section>
            </div>

            <section className="mapping-panel panel">
              <div className="mapping-heading"><div className="mapping-title"><div className="panel-icon mapping"><Sparkles size={15} /></div><div><h2>Reverse-tag map</h2><p>Values inferred from this message</p></div></div><span className="mapping-count">{analysis.replacements.length} MAPPINGS</span></div>
              <div className="mapping-list">
                {analysis.replacements.length ? analysis.replacements.slice(0, 7).map((replacement) => <div className="mapping-chip" key={`${replacement.value}-${replacement.tag}`}><span className="mapping-value" title={replacement.value}>{replacement.value}</span><ArrowRightLeft size={12} /><span className="mapping-tag">{replacement.tag}</span></div>) : <span className="mapping-empty">Mappings appear when sender, recipient, or routing values can be identified.</span>}
                {analysis.replacements.length > 7 && <span className="mapping-more">+{analysis.replacements.length - 7} more</span>}
              </div>
            </section>

            <footer className="page-footer"><span><LockKeyhole size={12} /> Processed locally in your browser</span><span>MAILROOM TOOLKIT <i>·</i> TEMPLATE LAB <i>·</i> V1.0</span></footer>
          </div>
        ) : (
          <div className="page-content ledger-content">
            <div className="page-heading">
              <div>
                <div className="eyebrow"><span className="eyebrow-dot" /> DELIVERABILITY TOOLKIT <span className="eyebrow-separator">/</span> 02</div>
                <h1>Infrastructure ledger</h1>
                <p>Keep operational notes, domain checks, and seed contacts in one place.</p>
              </div>
              <div className="heading-actions"><span className="local-save"><LockKeyhole size={13} /> Saved to this browser</span></div>
            </div>
            <div className="ledger-grid">
              <section className="panel ledger-card notes-card">
                <div className="ledger-card-heading"><div className="ledger-heading-icon notes"><StickyNote size={17} /></div><div><h2>Ops notes</h2><p>Keep the team in sync</p></div><button className="icon-button small" aria-label="Add note" onClick={() => setShowNoteForm(!showNoteForm)}><Plus size={16} /></button></div>
                {showNoteForm && <div className="note-form"><input value={newNoteTitle} onChange={(event) => setNewNoteTitle(event.target.value)} placeholder="Note title" aria-label="Note title" /><textarea value={newNoteBody} onChange={(event) => setNewNoteBody(event.target.value)} placeholder="Add a detail or next step..." aria-label="Note details" /><div><button className="text-button" onClick={() => setShowNoteForm(false)}>Cancel</button><button className="button button-primary compact" onClick={addNote}>Add note</button></div></div>}
                <div className="notes-list">
                  {notes.map((note) => <article className={`note-item ${note.done ? "complete" : ""}`} key={note.id}><button className="check-button" aria-label={note.done ? "Mark as active" : "Mark complete"} onClick={() => setNotes((current) => current.map((item) => item.id === note.id ? { ...item, done: !item.done } : item))}>{note.done && <Check size={12} />}</button><div className="note-content"><h3>{note.title}</h3><p>{note.body}</p><span>{note.done ? "COMPLETED" : "IN PROGRESS"}</span></div><button className="delete-note" aria-label={`Delete ${note.title}`} onClick={() => setNotes((current) => current.filter((item) => item.id !== note.id))}><Trash2 size={14} /></button></article>)}
                </div>
                <div className="card-footer"><span>{notes.length} notes</span><span>LOCAL ONLY</span></div>
              </section>

              <section className="panel ledger-card matrix-card">
                <div className="ledger-card-heading"><div className="ledger-heading-icon matrix"><UserRound size={17} /></div><div><h2>Seed contact matrix</h2><p>Generate 8 user × domain combinations</p></div><span className="matrix-count">{contacts.length} / 8</span></div>
                <div className="matrix-fields">
                  <label><span>USERNAMES <small>2</small></span><div className="input-pair"><div><UserRound size={14} /><input value={usernameOne} onChange={(event) => setUsernameOne(event.target.value)} placeholder="first user" aria-label="First username" /></div><div><UserRound size={14} /><input value={usernameTwo} onChange={(event) => setUsernameTwo(event.target.value)} placeholder="second user" aria-label="Second username" /></div></div></label>
                  <label><span>DOMAINS <small>4</small></span><div className="domain-entry"><Globe2 size={14} /><textarea value={domainsInput} onChange={(event) => setDomainsInput(event.target.value)} rows={4} aria-label="Four domains" /><span>{domains.length}/4</span></div></label>
                </div>
                <div className="matrix-output-heading"><span>GENERATED CONTACTS</span><button className="text-button" onClick={async () => { await navigator.clipboard.writeText(contacts.join("\n")); }}><Clipboard size={13} /> Copy list</button></div>
                <div className="contact-list">{contacts.map((contact, index) => <div className="contact-row" key={`${contact}-${index}`}><span className="contact-index">{String(index + 1).padStart(2, "0")}</span><Mail size={13} /><span>{contact}</span><span className="seed-label">SEED</span></div>)}</div>
                <div className="card-footer"><span>Cross-product list generated locally</span><span>NO DATA SYNC</span></div>
              </section>

              <section className="panel ledger-card checklist-card">
                <div className="ledger-card-heading"><div className="ledger-heading-icon checklist"><ListChecks size={17} /></div><div><h2>Preflight checklist</h2><p>Domain readiness checkpoints</p></div><span className="checklist-progress">2 / 4 DONE</span></div>
                <div className="checklist-items">
                {["SPF record aligned", "DKIM selector published", "DMARC policy reviewed", "Return-path MX verified"].map((item, index) => <label className="checklist-item" key={item}><input type="checkbox" checked={checklist[index]} onChange={() => setChecklist((current) => current.map((checked, itemIndex) => itemIndex === index ? !checked : checked))} /><span className="custom-check"><Check size={12} /></span><span>{item}</span><small>{checklist[index] ? "VERIFIED" : "PENDING"}</small></label>)}
                </div>
                <div className="card-footer"><span><Globe2 size={12} /> northstar.example</span><span>{checklist.filter(Boolean).length} / 4 DONE</span></div>
              </section>

              <section className="ledger-tip"><div><Inbox size={18} /></div><p><strong>Keep your infrastructure tidy.</strong> These notes and checklists are stored locally in this browser, so no operational data leaves your machine.</p><X size={15} /></section>
              {ledgerStorageError && <p className="storage-warning" role="status">Browser storage is unavailable or contains invalid ledger data. Changes may not persist after closing this page.</p>}
            </div>
            <footer className="page-footer"><span><LockKeyhole size={12} /> Workspace data stays on this device</span><span>MAILROOM TOOLKIT <i>·</i> INFRASTRUCTURE LEDGER <i>·</i> V1.0</span></footer>
          </div>
        )}
      </section>
    </main>
  );
}
