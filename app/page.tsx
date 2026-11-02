"use client";

import { Check, Clipboard, Mail, ShieldCheck, WandSparkles } from "lucide-react";
import { useMemo, useState } from "react";
import { analyzeEmail, AuditItem, EmailAnalysis, makeContactMatrix } from "@/lib/email-engine";

type ToolTab = "sanitizer" | "matrix";
type OutputSection = "template" | "header" | "body" | "footer";

const defaultUsers = ["user1", "user2"];
const defaultDomains = [
  "domain1.example",
  "domain2.example",
  "domain3.example",
  "domain4.example"
];

function AuditList({ items }: { items: AuditItem[] }) {
  if (!items.length) {
    return <p className="empty-message">No transport headers extracted.</p>;
  }

  return (
    <ol className="audit-list">
      {items.map((item, index) => (
        <li className="audit-item" key={`${item.name}-${index}`}>
          <div className="audit-meta">
            <strong>{item.name}</strong>
            <span>{item.category}</span>
          </div>
          <p>{item.value}</p>
        </li>
      ))}
    </ol>
  );
}

export default function Home() {
  const [activeTab, setActiveTab] = useState<ToolTab>("sanitizer");
  const [rawSource, setRawSource] = useState("");
  const [analysis, setAnalysis] = useState<EmailAnalysis | null>(null);
  const [outputSection, setOutputSection] = useState<OutputSection>("template");
  const [users, setUsers] = useState(defaultUsers);
  const [domains, setDomains] = useState(defaultDomains);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "error">("idle");
  const [message, setMessage] = useState("");

  const contacts = useMemo(() => makeContactMatrix(users, domains), [users, domains]);

  const sanitize = () => {
    if (!rawSource.trim()) {
      setAnalysis(null);
      setMessage("Paste an email source before sanitizing.");
      return;
    }

    setAnalysis(analyzeEmail(rawSource));
    setOutputSection("template");
    setMessage("");
  };

  const copyText = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopyState("copied");
      window.setTimeout(() => setCopyState("idle"), 1400);
    } catch {
      setCopyState("error");
      window.setTimeout(() => setCopyState("idle"), 2500);
    }
  };

  const updateUser = (index: number, value: string) => {
    setUsers((current) => current.map((user, itemIndex) => itemIndex === index ? value : user));
  };

  const updateDomain = (index: number, value: string) => {
    setDomains((current) => current.map((domain, itemIndex) => itemIndex === index ? value : domain));
  };

  return (
    <main className="app-shell min-h-screen">
      <header className="top-header">
        <a className="brand" href="/" aria-label="Mailroom utilities">
          <span className="brand-mark"><Mail size={17} /></span>
          <span>MAILROOM</span>
        </a>
        <nav className="top-nav" aria-label="Utilities">
          <button
            type="button"
            className={`nav-tab ${activeTab === "sanitizer" ? "active" : ""}`}
            onClick={() => setActiveTab("sanitizer")}
          >
            <span className="tab-index">1</span>
            <span>Raw Email Sanitizer &amp; Reverse-Tag Engine</span>
          </button>
          <button
            type="button"
            className={`nav-tab ${activeTab === "matrix" ? "active" : ""}`}
            onClick={() => setActiveTab("matrix")}
          >
            <span className="tab-index">2</span>
            <span>8-Contact Matrix Generator</span>
          </button>
        </nav>
        <span className="local-indicator"><ShieldCheck size={14} /> LOCAL PROCESSING</span>
      </header>

      {activeTab === "sanitizer" ? (
        <section className="tool-content">
          <div className="tool-heading">
            <div>
              <span className="section-index">TOOL 01</span>
              <h1>Raw Email Sanitizer &amp; Reverse-Tag Engine</h1>
              <p>Remove delivery noise and recover reusable template values.</p>
            </div>
            <button type="button" className="action-button" onClick={sanitize}>
              <WandSparkles size={16} />
              Sanitize &amp; Reverse Engine
            </button>
          </div>

          <div className="sanitize-grid">
            <section className="tool-panel source-panel">
              <div className="panel-heading">
                <h2>Raw email source</h2>
                <span>RFC 5322</span>
              </div>
              <textarea
                className="source-input w-full"
                aria-label="Raw email source"
                autoCapitalize="off"
                autoCorrect="off"
                spellCheck={false}
                value={rawSource}
                onChange={(event) => {
                  setRawSource(event.target.value);
                  setAnalysis(null);
                  setMessage("");
                }}
                placeholder={"Paste fully-sent email source here...\n\nInclude the original headers, MIME content, and any transport headers."}
              />
              <div className="panel-footer">
                <span>{rawSource.length.toLocaleString()} characters</span>
                {message && <span className="error-message" role="status">{message}</span>}
              </div>
            </section>

            <section className="tool-panel result-panel">
              <div className="panel-heading">
                <h2>Recovered template</h2>
                {analysis && (
                  <button
                    type="button"
                    className="quiet-button"
                    disabled={outputSection !== "template" && !analysis.sections[outputSection]}
                    onClick={() => void copyText(
                      outputSection === "template"
                        ? analysis.cleanedTemplate
                        : analysis.sections[outputSection]
                    )}
                  >
                    {copyState === "copied" ? <Check size={14} /> : <Clipboard size={14} />}
                    {copyState === "copied"
                      ? "Copied"
                      : copyState === "error"
                        ? "Copy failed"
                        : `Copy ${outputSection === "template" ? "template" : outputSection}`}
                  </button>
                )}
              </div>
              {analysis && (
                <nav className="section-tabs" aria-label="Recovered template sections">
                  {([
                    ["template", "Full template"],
                    ["header", "Header Section"],
                    ["body", "Body Section"],
                    ["footer", "Footer Section"]
                  ] as const).map(([section, label]) => (
                    <button
                      type="button"
                      key={section}
                      className={outputSection === section ? "selected" : ""}
                      onClick={() => setOutputSection(section)}
                    >
                      {label}
                    </button>
                  ))}
                </nav>
              )}
              <pre className={`result-output ${analysis ? "" : "placeholder-output"}`}>
                {!analysis
                  ? "Sanitized template output will appear here."
                  : outputSection === "template"
                    ? analysis.cleanedTemplate
                    : analysis.sections[outputSection] || `No ${outputSection} section was detected.`}
              </pre>
              <div className="panel-footer">
                {analysis
                  ? outputSection === "template"
                    ? `${analysis.replacements.length} value mappings · ${analysis.detectedTags.length} tags`
                    : `${analysis.sections[outputSection].length.toLocaleString()} characters · ${outputSection} section`
                  : "Output is generated on request"}
              </div>
            </section>

            <section className="tool-panel audit-panel">
              <div className="panel-heading">
                <h2>Stripped Elements</h2>
                <span>{analysis ? `${analysis.audit.length} elements` : "AUDIT"}</span>
              </div>
              {analysis
                ? <AuditList items={analysis.audit} />
                : <p className="empty-message">Removed transport headers and webmail delivery wrappers will be listed here.</p>}
            </section>
          </div>
        </section>
      ) : (
        <section className="tool-content matrix-content">
          <div className="tool-heading">
            <div>
              <span className="section-index">TOOL 02</span>
              <h1>8-Contact Matrix Generator</h1>
              <p>Cross-multiply two usernames and four domains into a seed list.</p>
            </div>
          </div>

          <div className="matrix-layout">
            <section className="tool-panel matrix-input-panel">
              <div className="matrix-section">
                <div className="panel-heading">
                  <h2>Usernames</h2>
                  <span>2 INPUTS</span>
                </div>
                <div className="input-grid two-columns">
                  {users.map((user, index) => (
                    <label className="field" key={`user-${index}`}>
                      <span>Username {index + 1}</span>
                      <input
                        value={user}
                        onChange={(event) => updateUser(index, event.target.value)}
                        placeholder={`user${index + 1}`}
                        aria-label={`Username ${index + 1}`}
                      />
                    </label>
                  ))}
                </div>
              </div>
              <div className="matrix-section">
                <div className="panel-heading">
                  <h2>Domains</h2>
                  <span>4 INPUTS</span>
                </div>
                <div className="input-grid two-columns">
                  {domains.map((domain, index) => (
                    <label className="field" key={`domain-${index}`}>
                      <span>Domain {index + 1}</span>
                      <input
                        value={domain}
                        onChange={(event) => updateDomain(index, event.target.value)}
                        placeholder={`domain${index + 1}.example`}
                        aria-label={`Domain ${index + 1}`}
                      />
                    </label>
                  ))}
                </div>
              </div>
            </section>

            <section className="tool-panel contacts-panel">
              <div className="panel-heading">
                <div>
                  <h2>Generated contacts</h2>
                  <span className="result-count">{contacts.length} / 8 unique combinations</span>
                </div>
                <button
                  type="button"
                  className="action-button copy-all"
                  onClick={() => void copyText(contacts.join("\n"))}
                  disabled={!contacts.length}
                >
                  {copyState === "copied" ? <Check size={15} /> : <Clipboard size={15} />}
                  {copyState === "copied" ? "Copied" : copyState === "error" ? "Copy failed" : "Copy All"}
                </button>
              </div>
              {contacts.length
                ? <ol className="contact-list">{contacts.map((contact, index) => (
                    <li key={`${contact}-${index}`}>
                      <span className="contact-number">{String(index + 1).padStart(2, "0")}</span>
                      <span>{contact}</span>
                    </li>
                  ))}</ol>
                : <p className="empty-message">Enter at least one username and one domain.</p>}
            </section>
          </div>
        </section>
      )}
    </main>
  );
}
