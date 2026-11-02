export type AuditItem = {
  name: string;
  value: string;
  category: "routing" | "delivery" | "authentication" | "metadata";
};

export type Replacement = {
  value: string;
  tag: string;
  source: string;
  caseSensitive?: boolean;
};

export type EmailAnalysis = {
  cleanedTemplate: string;
  sections: {
    header: string;
    body: string;
    footer: string;
  };
  audit: AuditItem[];
  replacements: Replacement[];
  detectedTags: string[];
  headerCount: number;
};

type HeaderBlock = {
  name: string;
  value: string;
  raw: string;
};

type PreparedSource = {
  source: string;
  wrapperAudit: AuditItem[];
};

type HtmlSections = {
  header: string;
  body: string;
  footer: string;
};

type HtmlPartition = {
  sections: HtmlSections;
  cleanedHtml: string;
};

export const TAG_DICTIONARY = [
  "__Rand(min,max)",
  "__Chr(num)",
  "__Random_nm[len]",
  "__Random_al[len,case]",
  "__Random_anm[len,type]",
  "__smtpDateZone[Timezone@Format@Offset]",
  "DynTag1",
  "DynTag2",
  "DynTag3",
  "User",
  "__Link",
  "__Link64",
  "__LinkU",
  "__Str",
  "__User",
  "__StateS",
  "__To",
  "__ToU",
  "__ToE",
  "__md5_eml",
  "__X-smfbl",
  "__Ip",
  "__MainDomainName",
  "__Bounce_dn",
  "__From_dn",
  "__rDNS",
  "user_dom",
  "__Bounce_dns",
  "[extradom]",
  "__ServerProcessId",
  "__From_from_Data",
  "__Msgid_from_Data",
  "__Rp_from_Data",
  "__exmpl",
  "__exmRpT",
  "__From_email",
  "__Alphanum",
  "__Returnpath",
  "__Reply-To",
  "__Subject",
  "__From_nm",
  "__From",
  "__X-Mailer",
  "__Date",
  "__smtpDate",
  "__Uniqid"
] as const;

const namedTags = [
  "User",
  "Link",
  "Link64",
  "LinkU",
  "Str",
  "StateS",
  "To",
  "ToU",
  "ToE",
  "md5_eml",
  "X-smfbl",
  "Ip",
  "MainDomainName",
  "Bounce_dn",
  "From_dn",
  "rDNS",
  "Bounce_dns",
  "ServerProcessId",
  "From_from_Data",
  "Msgid_from_Data",
  "Rp_from_Data",
  "exmpl",
  "exmRpT",
  "From_email",
  "Alphanum",
  "Returnpath",
  "Reply-To",
  "Subject",
  "From_nm",
  "From",
  "X-Mailer",
  "Date",
  "smtpDate",
  "Uniqid"
].sort((left, right) => right.length - left.length).join("|");

const tagPattern = new RegExp(
  `DynTag[1-3]|\\bUser\\b|__(?:Rand\\(\\s*\\d+\\s*,\\s*\\d+\\s*\\)|Chr\\(\\s*\\d+\\s*\\)|Random_nm\\[\\s*\\d+\\s*\\]|Random_al\\[\\s*\\d+\\s*,\\s*[^\\]]+\\]|Random_anm\\[\\s*\\d+\\s*,\\s*[^\\]]+\\]|smtpDateZone\\[[^\\]]+\\]|${namedTags})|user_dom|\\[extradom\\]`,
  "g"
);

const transportHeaders = new Map<string, AuditItem["category"]>([
  ["received", "routing"],
  ["received-spf", "authentication"],
  ["authentication-results", "authentication"],
  ["arc-authentication-results", "authentication"],
  ["arc-message-signature", "authentication"],
  ["arc-seal", "authentication"],
  ["return-path", "delivery"],
  ["delivered-to", "delivery"],
  ["x-original-to", "delivery"],
  ["delivery-date", "delivery"],
  ["resent-date", "delivery"],
  ["x-received", "routing"],
  ["x-google-smtp-source", "routing"],
  ["x-ms-exchange-transport-endtoendlatency", "metadata"],
  ["x-ms-exchange-organization-network-message-id", "metadata"],
  ["x-serverprocessid", "metadata"],
  ["x-server-process-id", "metadata"],
  ["x-drop-id", "metadata"],
  ["x-dropid", "metadata"],
  ["x-mailer-daemon", "delivery"]
]);

const transportHeaderPattern =
  /^(?:x-)?(?:mta|smtp|queue|relay|delivery|transport|trace|spam|antispam|virus|filter|dkim|dmarc|spf|feedback|complaint|original-authentication)-/i;

function splitHeaderBlocks(rawHeaders: string): HeaderBlock[] {
  const lines = rawHeaders.split(/\r?\n/);
  const blocks: string[] = [];

  for (const line of lines) {
    if (/^[ \t]/.test(line) && blocks.length > 0) {
      blocks[blocks.length - 1] += `\n${line}`;
    } else {
      blocks.push(line);
    }
  }

  return blocks.flatMap((raw) => {
    const separator = raw.indexOf(":");
    if (separator <= 0) return [];
    return [{
      name: raw.slice(0, separator).trim(),
      value: raw.slice(separator + 1).replace(/\r?\n[ \t]+/g, " ").trim(),
      raw
    }];
  });
}

function isTransportHeader(name: string): boolean {
  const normalized = name.toLowerCase();
  return transportHeaders.has(normalized) || transportHeaderPattern.test(normalized);
}

function auditCategory(name: string): AuditItem["category"] {
  const normalized = name.toLowerCase();
  const known = transportHeaders.get(normalized);
  if (known) return known;
  if (/auth|dkim|dmarc|spf/i.test(normalized)) return "authentication";
  if (/delivery|return-path|delivered|complaint/i.test(normalized)) return "delivery";
  if (/^received|relay|route|transport|queue|mta/i.test(normalized)) return "routing";
  return "metadata";
}

function classifyWrapperLine(line: string): AuditItem | null {
  const value = line.trim();
  if (!value) return null;
  if (/^created\s+at\s*:/i.test(value)) {
    return { name: "Webmail wrapper · Created at", value, category: "metadata" };
  }
  if (/^delivered\s+after\s+[\d.]+\s*(?:seconds?|secs?)/i.test(value)) {
    return { name: "Webmail wrapper · Delivery time", value, category: "delivery" };
  }
  if (/^(?:spf|dkim|dmarc)\s*:\s*(?:pass|fail|softfail|neutral|none|temperror|permerror)\b/i.test(value)) {
    return { name: "Webmail wrapper · Authentication result", value, category: "authentication" };
  }
  if (/^(?:download\s+original(?:\s*\/\s*copy\s+to\s+clipboard)?|copy\s+to\s+clipboard)\s*$/i.test(value)) {
    return { name: "Webmail wrapper · Client action", value, category: "metadata" };
  }
  return null;
}

function stripDeliveryWrapper(source: string): PreparedSource {
  const lines = source.split("\n");
  const wrapperAudit: AuditItem[] = [];
  let firstContentLine = 0;
  let foundWrapper = false;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) {
      if (foundWrapper) {
        firstContentLine = index + 1;
        continue;
      }
      firstContentLine = index + 1;
      continue;
    }

    const wrapper = classifyWrapperLine(line);
    if (!wrapper) {
      if (!foundWrapper) firstContentLine = index;
      break;
    }

    foundWrapper = true;
    wrapperAudit.push(wrapper);
    firstContentLine = index + 1;
  }

  return {
    source: lines.slice(firstContentLine).join("\n").replace(/^\s+/, ""),
    wrapperAudit
  };
}

function parseAddress(value: string): { displayName: string; email: string } | null {
  const match = value.match(/[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?)+/i);
  if (!match) return null;
  const email = match[0].replace(/^mailto:/i, "");
  const displayName = value
    .replace(match[0], "")
    .replace(/^[\s"'<>]+|[\s"'<>]+$/g, "")
    .trim();
  return { displayName, email };
}

function encodeBase64(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function md5(value: string): string {
  const bytes = new TextEncoder().encode(value);
  const bitLength = bytes.length * 8;
  const paddedLength = Math.ceil((bytes.length + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLength);
  padded.set(bytes);
  padded[bytes.length] = 0x80;

  const view = new DataView(padded.buffer);
  view.setUint32(paddedLength - 8, bitLength >>> 0, true);
  view.setUint32(paddedLength - 4, Math.floor(bitLength / 0x100000000), true);

  const shifts = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  ];
  const constants = Array.from({ length: 64 }, (_, index) =>
    Math.floor(Math.abs(Math.sin(index + 1)) * 0x100000000) >>> 0
  );
  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;

  for (let offset = 0; offset < paddedLength; offset += 64) {
    let a = a0;
    let b = b0;
    let c = c0;
    let d = d0;

    for (let index = 0; index < 64; index += 1) {
      let fn: number;
      let wordIndex: number;
      if (index < 16) {
        fn = (b & c) | (~b & d);
        wordIndex = index;
      } else if (index < 32) {
        fn = (d & b) | (~d & c);
        wordIndex = (5 * index + 1) % 16;
      } else if (index < 48) {
        fn = b ^ c ^ d;
        wordIndex = (3 * index + 5) % 16;
      } else {
        fn = c ^ (b | ~d);
        wordIndex = (7 * index) % 16;
      }

      const word = view.getUint32(offset + wordIndex * 4, true);
      const sum = (a + fn + constants[index] + word) >>> 0;
      const rotated = (sum << shifts[index]) | (sum >>> (32 - shifts[index]));
      [a, d, c, b] = [d, c, b, (b + rotated) >>> 0];
    }

    a0 = (a0 + a) >>> 0;
    b0 = (b0 + b) >>> 0;
    c0 = (c0 + c) >>> 0;
    d0 = (d0 + d) >>> 0;
  }

  return [a0, b0, c0, d0]
    .map((word) => [0, 8, 16, 24].map((shift) => ((word >>> shift) & 0xff).toString(16).padStart(2, "0")).join(""))
    .join("");
}

function addReplacement(
  replacements: Map<string, Replacement>,
  value: string | undefined,
  tag: string,
  source: string,
  minimumLength = 2,
  caseSensitive = false
) {
  const trimmed = value?.trim();
  if (!trimmed || trimmed.length < minimumLength || /^__(?:[A-Za-z]|Rand|Chr|Random)/.test(trimmed)) return;
  const key = `${caseSensitive ? trimmed : trimmed.toLowerCase()}|${caseSensitive}`;
  if (!replacements.has(key)) replacements.set(key, { value: trimmed, tag, source, caseSensitive });
}

function getRootDomain(domain: string): string {
  const parts = domain.toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) return domain;
  const commonTwoPartSuffixes = new Set([
    "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "org.au",
    "co.nz", "com.br", "com.cn", "co.jp", "co.in"
  ]);
  const suffix = parts.slice(-2).join(".");
  return parts.slice(commonTwoPartSuffixes.has(suffix) ? -3 : -2).join(".");
}

function deriveReplacements(headers: HeaderBlock[], audit: AuditItem[], body: string): Replacement[] {
  const replacements = new Map<string, Replacement>();
  const first = (name: string) => headers.find((header) => header.name.toLowerCase() === name);
  const from = parseAddress(first("from")?.value ?? "");
  const to = parseAddress(first("to")?.value ?? "");
  const replyTo = parseAddress(first("reply-to")?.value ?? "");
  const returnPath = parseAddress(audit.find((item) => item.name.toLowerCase() === "return-path")?.value ?? "");

  if (from) {
    const domain = from.email.split("@")[1];
    const rootDomain = getRootDomain(domain);
    addReplacement(replacements, from.email, "__From_email", "From header");
    addReplacement(replacements, from.displayName, "__From_nm", "From header");
    addReplacement(replacements, rootDomain, "__MainDomainName", "From address root domain");
    addReplacement(replacements, domain, "__From_dn", "From address domain");
  }

  if (to) {
    const [username, domain] = to.email.split("@");
    addReplacement(replacements, to.email.toLowerCase(), "__To", "To header");
    addReplacement(replacements, to.email.toUpperCase(), "__ToU", "Uppercase To address", 2, true);
    addReplacement(replacements, to.email.replace("@", "="), "__ToE", "To address with @ replaced by =");
    addReplacement(replacements, username, "__Link", "To address username");
    addReplacement(replacements, username.toUpperCase(), "__LinkU", "Uppercase To address username", 2, true);
    addReplacement(replacements, encodeBase64(username), "__Link64", "Base64 To address username");
    addReplacement(replacements, md5(username), "__md5_eml", "MD5 To address username", 32);
    addReplacement(replacements, encodeBase64(to.email), "__X-smfbl", "Base64 To address");
    addReplacement(replacements, domain, "user_dom", "To address domain");
    addReplacement(replacements, getRootDomain(domain), "__MainDomainName", "To address root domain");
  }

  if (replyTo) addReplacement(replacements, replyTo.email, "__Reply-To", "Reply-To header");

  if (returnPath) {
    const domain = returnPath.email.split("@")[1];
    addReplacement(replacements, returnPath.email, "__Returnpath", "Return-Path header");
    addReplacement(replacements, domain, "__Bounce_dn", "Return-Path domain");
    addReplacement(replacements, getRootDomain(domain), "__Bounce_dns", "Return-Path root domain");
    addReplacement(replacements, returnPath.email.replace("@", "."), "__exmRpT", "Return-Path with @ replaced by .");
  }

  const unsubscribeHosts = new Set<string>();
  for (const match of body.matchAll(/(?:https?:)?\/\/[^\s"'<>)]*/gi)) {
    const url = match[0].replace(/&amp;/gi, "&");
    if (!/(?:un-?subscribe|opt[\s_-]?out)/i.test(url)) continue;
    const hostname = url.match(/^(?:https?:)?\/\/([^/:?#]+)/i)?.[1]?.toLowerCase();
    if (hostname) unsubscribeHosts.add(hostname);
  }
  for (const hostname of unsubscribeHosts) {
    addReplacement(replacements, hostname, "__Bounce_dn", "Unsubscribe link domain");
  }

  const bodyDomains = new Set(
    [...body.matchAll(/(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?![\w.-])/gi)]
      .map((match) => match[0].toLowerCase())
  );
  const assetExtensions = new Set([
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "css", "js",
    "woff", "woff2", "ttf", "eot", "pdf"
  ]);
  for (const domain of bodyDomains) {
    if (assetExtensions.has(domain.split(".").pop() ?? "")) continue;
    if (unsubscribeHosts.has(domain)) continue;
    addReplacement(replacements, domain, "__MainDomainName", "Email body domain");
  }

  for (const item of audit) {
    if (item.name.toLowerCase() !== "received") continue;
    const ip = item.value.match(/\[([0-9a-f:.]+)\]/i)?.[1];
    const hostname = item.value.match(/\bfrom\s+([a-z0-9.-]+\.[a-z]{2,})\b/i)?.[1];
    addReplacement(replacements, ip, "__Ip", "Received routing header");
    addReplacement(replacements, hostname, "__rDNS", "Received routing header");
  }

  const messageId = first("message-id")?.value.match(/<([^>]+)>/)?.[1];
  addReplacement(replacements, messageId, "__Msgid_from_Data", "Message-ID header");
  addReplacement(replacements, first("x-mailer")?.value, "__X-Mailer", "X-Mailer header");
  addReplacement(replacements, first("date")?.value, "__smtpDate", "Date header");
  addReplacement(replacements, first("subject")?.value, "__Subject", "Subject header");
  addReplacement(
    replacements,
    audit.find((item) => /^(?:x-serverprocessid|x-server-process-id|x-drop-id|x-dropid)$/i.test(item.name))?.value,
    "__ServerProcessId",
    "Drop ID transport header"
  );

  for (const match of body.matchAll(/[?&]extradom=([^&#\s"'<>]+)/gi)) {
    addReplacement(replacements, match[1], "[extradom]", "extradom body parameter");
  }
  for (const match of body.matchAll(/[?&](?:exmpl|rotate)=([^&#\s"'<>]+)/gi)) {
    addReplacement(replacements, match[1], "__exmpl", "Rotating sender body parameter");
  }
  for (const match of body.matchAll(/[?&](?:id|uid|uuid|clickid|track(?:ing)?id|token|cid)=([a-z0-9_-]{6,})/gi)) {
    const tag = match[1].length >= 24 ? "__Uniqid" : "__Alphanum";
    addReplacement(replacements, match[1], tag, "Tracking query parameter", tag === "__Uniqid" ? 24 : 6);
  }
  const dateValues = body.match(/\b\d{4}\.\d{2}\.\d{2}-\d{2}\.\d{2}\.\d{2}\b/g) ?? [];
  for (const value of dateValues) {
    addReplacement(replacements, value, "__Date", "Formatted date value");
  }

  const alphaNumericValues = body.match(/(?<![A-Za-z0-9@.-])(?=[A-Za-z0-9]{32}(?![A-Za-z0-9@-]|\.(?=[A-Za-z])))(?=[A-Za-z0-9]*\d)[A-Za-z0-9]{32}/g) ?? [];
  for (const value of alphaNumericValues) {
    addReplacement(replacements, value, "__Uniqid", "32-character unique value", 32);
  }

  const shortUniqueValues = body.match(/(?<![A-Za-z0-9@.-])(?=[A-Za-z0-9]{10}(?![A-Za-z0-9@-]|\.(?=[A-Za-z])))(?=[A-Za-z0-9]*\d)[A-Za-z0-9]{10}/g) ?? [];
  for (const value of shortUniqueValues) {
    addReplacement(replacements, value, "__Alphanum", "10-character alphanumeric value", 10);
  }

  return [...replacements.values()].sort((left, right) =>
    right.value.length - left.value.length
    || Number(right.caseSensitive ?? false) - Number(left.caseSensitive ?? false)
  );
}

function replaceValues(text: string, replacements: Replacement[]): string {
  return replacements.reduce((result, replacement) => {
    const escaped = replacement.value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const wordBoundary = /^[\w.+-]+@[\w.-]+$/.test(replacement.value) || replacement.value.includes(".")
      ? "(?<![\\w.+-])"
      : "(?<![\\w])";
    const endBoundary = /^[\w.+-]+@[\w.-]+$/.test(replacement.value) || replacement.value.includes(".")
      ? "(?![\\w.+-])"
      : "(?![\\w])";
    const flags = replacement.caseSensitive ? "g" : "gi";
    return result.replace(new RegExp(`${wordBoundary}${escaped}${endBoundary}`, flags), replacement.tag);
  }, text);
}

const headerDatePattern =
  /\b(?:\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?|\d{4}\.\d{2}\.\d{2}(?:-\d{2}\.\d{2}\.\d{2})?|\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4}(?:\s+\d{2}:\d{2}(?::\d{2})?(?:\s+[+-]\d{4}|\s+(?:GMT|UTC))?)?)/gi;

function replaceHeaderDates(header: string): string {
  return header.replace(headerDatePattern, (value) => {
    const includesTime = /(?:T|\s)\d{2}:\d{2}|-\d{2}\.\d{2}\.\d{2}/i.test(value);
    return includesTime ? "__smtpDate" : "__Date";
  });
}

function getNodeDescription(element: Element): string {
  const attributes = [
    element.getAttribute("class") ?? "",
    element.getAttribute("id") ?? "",
    element.getAttribute("role") ?? "",
    element.getAttribute("aria-label") ?? "",
    element.getAttribute("style") ?? "",
    element.hasAttribute("hidden") ? "hidden" : ""
  ].join(" ");
  const text = (element.textContent ?? "").replace(/\s+/g, " ").trim();
  const links = Array.from(element.querySelectorAll("a[href]"));
  const hrefs = links.map((link) => link.getAttribute("href") ?? "").join(" ");
  const imageCount = element.querySelectorAll("img").length;
  return `${attributes} ${text} ${hrefs} ${imageCount ? "image" : ""}`;
}

function classifyHtmlElement(element: Element, index: number): keyof HtmlSections {
  const detail = getNodeDescription(element);
  const text = (element.textContent ?? "").replace(/\s+/g, " ").trim();
  if (
    /unsubscribe|un-subscribe|opt[\s_-]?out|privacy policy|all rights reserved|copyright|postal address|legal disclaimer/i.test(detail)
    || /\b\d{1,6}\s+[\w.-]+(?:\s+[\w.-]+){0,3}\s+(?:street|st|avenue|ave|road|rd|boulevard|blvd|drive|dr|lane|ln|suite|ste)\b/i.test(text)
    || /\b(?:postal address|mailing address|©\s*\d{4})/i.test(text)
  ) {
    return "footer";
  }
  if (/\b(?:header|masthead|preheader|pre-header|brand(?:ing)?|navigation|navbar|intro|banner)\b|display\s*:\s*none|visibility\s*:\s*hidden|(?:^|\s)hidden(?:\s|$)/i.test(detail)) {
    return "header";
  }

  const linkCount = element.querySelectorAll("a[href]").length;
  const hasImage = element.querySelector("img") !== null;
  const shortIntro = text.length <= 160 && !/https?:\/\//i.test(text) && (
    hasImage
    || (linkCount > 1 && text.length < 180)
    || /^(hi|hello|dear|welcome)\b[^.!?]{0,80}[,!]?$/i.test(text)
  );
  if (index < 2 && shortIntro) return "header";
  return "body";
}

function partitionHtml(html: string): HtmlPartition {
  const sections: HtmlSections = { header: "", body: "", footer: "" };
  if (typeof DOMParser === "undefined") {
    return { sections: { ...sections, body: html }, cleanedHtml: html };
  }

  const document = new DOMParser().parseFromString(html, "text/html");
  const rootTables = Array.from(document.body.querySelectorAll("table"))
    .filter((table) => table.parentElement?.closest("table") === null);
  const splitTable = rootTables
    .flatMap((table) => Array.from(table.rows).length > 1 ? [table] : [])
    .sort((left, right) => right.rows.length - left.rows.length)[0];

  if (splitTable) {
    const groupedRows: Record<keyof HtmlSections, HTMLTableRowElement[]> = {
      header: [],
      body: [],
      footer: []
    };
    Array.from(splitTable.rows).forEach((row, index) => {
      groupedRows[classifyHtmlElement(row, index)].push(row);
    });

    for (const section of ["header", "body", "footer"] as const) {
      if (!groupedRows[section].length) continue;
      const wrapper = splitTable.cloneNode(false) as HTMLTableElement;
      const tbody = document.createElement("tbody");
      groupedRows[section].forEach((row) => tbody.appendChild(row.cloneNode(true)));
      wrapper.appendChild(tbody);
      sections[section] = wrapper.outerHTML;
    }
    return {
      sections,
      cleanedHtml: html.replace(
        /(<body\b[^>]*>)[\s\S]*?(<\/body\s*>)/i,
        (_match, opening: string, closing: string) =>
          `${opening}${sections.header}${sections.body}${sections.footer}${closing}`
      )
    };
  }

  const flattenWrappers = (parent: Element): Element[] =>
    Array.from(parent.children).flatMap((child) => {
      const isWrapper = /^(DIV|SECTION|MAIN)$/.test(child.tagName);
      if (isWrapper && child.children.length > 0) return flattenWrappers(child);
      return [child];
    });
  const elements = flattenWrappers(document.body);
  elements.forEach((element, index) => {
    const section = classifyHtmlElement(element, index);
    sections[section] += element.outerHTML;
  });
  if (!sections.header && !sections.body && !sections.footer) sections.body = html;
  return {
    sections,
    cleanedHtml: html.replace(
      /(<body\b[^>]*>)[\s\S]*?(<\/body\s*>)/i,
      (_match, opening: string, closing: string) =>
        `${opening}${sections.header}${sections.body}${sections.footer}${closing}`
    )
  };
}

function getHtmlFragment(body: string): { prefix: string; html: string; suffix: string } | null {
  const htmlMatch = /<html\b[^>]*>[\s\S]*?<\/html\s*>/i.exec(body);
  if (htmlMatch) {
    return {
      prefix: body.slice(0, htmlMatch.index),
      html: htmlMatch[0],
      suffix: body.slice(htmlMatch.index + htmlMatch[0].length)
    };
  }
  const bodyMatch = /<body\b[^>]*>[\s\S]*?<\/body\s*>/i.exec(body);
  if (bodyMatch) {
    return {
      prefix: body.slice(0, bodyMatch.index),
      html: bodyMatch[0],
      suffix: body.slice(bodyMatch.index + bodyMatch[0].length)
    };
  }
  return null;
}

function getDetectedTags(text: string): string[] {
  return [...new Set(text.match(tagPattern) ?? [])];
}

const templateHeaderTags: Record<string, string> = {
  from: "__From",
  to: "__To",
  "return-path": "__Returnpath",
  "reply-to": "__Reply-To",
  subject: "__Subject",
  date: "__smtpDate",
  "x-mailer": "__X-Mailer",
  "message-id": "__Msgid_from_Data"
};

function cleanHeaders(headers: HeaderBlock[], replacements: Replacement[]): string[] {
  return headers.flatMap((header) => {
    const name = header.name.toLowerCase();
    if (isTransportHeader(header.name) && name !== "return-path") return [];
    const tag = templateHeaderTags[name];
    if (tag) return [`${header.name}: ${tag}`];
    return [replaceHeaderDates(replaceValues(header.raw, replacements))];
  });
}

export function analyzeEmail(raw: string): EmailAnalysis {
  const prepared = stripDeliveryWrapper(raw.replace(/\r\n?/g, "\n"));
  const normalized = prepared.source;
  const separator = normalized.indexOf("\n\n");
  if (separator < 0) {
    const headers = splitHeaderBlocks(normalized);
    if (headers.length) {
      const audit = prepared.wrapperAudit.concat(headers
        .filter((header) => isTransportHeader(header.name))
        .map((header) => ({
          name: header.name,
          value: header.value,
          category: auditCategory(header.name)
        })));
      const replacements = deriveReplacements(headers, audit, "");
      const cleanedTemplate = cleanHeaders(headers, replacements).join("\n");
      return {
        cleanedTemplate,
        sections: { header: "", body: "", footer: "" },
        audit,
        replacements,
        detectedTags: getDetectedTags(cleanedTemplate),
        headerCount: headers.length
      };
    }
    return {
      cleanedTemplate: normalized,
      sections: { header: "", body: normalized, footer: "" },
      audit: prepared.wrapperAudit,
      replacements: [],
      detectedTags: getDetectedTags(normalized),
      headerCount: 0
    };
  }

  const allHeaders = splitHeaderBlocks(normalized.slice(0, separator));
  const body = normalized.slice(separator + 2);
  const audit = prepared.wrapperAudit.concat(allHeaders
    .filter((header) => isTransportHeader(header.name))
    .map((header) => ({
      name: header.name,
      value: header.value,
      category: auditCategory(header.name)
    })));
  const replacements = deriveReplacements(allHeaders, audit, body);
  const cleanedHeaders = cleanHeaders(allHeaders, replacements);
  const mappedBody = replaceValues(body, replacements);
  const htmlFragment = getHtmlFragment(mappedBody);
  const partition = htmlFragment
    ? partitionHtml(htmlFragment.html)
    : {
      sections: { header: "", body: mappedBody, footer: "" },
      cleanedHtml: mappedBody
    };
  const bodyOutput = htmlFragment
    ? `${htmlFragment.prefix}${partition.cleanedHtml}${htmlFragment.suffix}`
    : mappedBody;
  const cleanedTemplate = `${cleanedHeaders.join("\n")}\n\n${bodyOutput}`;

  return {
    cleanedTemplate,
    sections: partition.sections,
    audit,
    replacements,
    detectedTags: getDetectedTags(cleanedTemplate),
    headerCount: allHeaders.length
  };
}

export function makeContactMatrix(usernames: string[], domains: string[]): string[] {
  const contacts = usernames.flatMap((username) =>
    domains.map((domain) => `${username.trim()}@${domain.trim()}`)
  );
  return [...new Set(contacts)];
}
