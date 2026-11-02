export type AuditItem = {
  name: string;
  value: string;
  category: "routing" | "delivery" | "authentication" | "metadata";
};

export type Replacement = {
  value: string;
  tag: string;
  source: string;
};

export type EmailAnalysis = {
  cleanedTemplate: string;
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
  ["x-mailer-daemon", "delivery"]
]);

const transportHeaderPattern =
  /^(?:x-)?(?:mta|smtp|queue|relay|delivery|transport|trace|spam|antispam|virus|filter|dkim|dmarc|spf|feedback|complaint|original-authentication)-/i;

const tagPattern =
  /__(?:Random_al\[\s*\d+\s*,\s*[^\]]+\]|Random_nm\[\s*\d+\s*\]|smtpDateZone\[[^\]]+\]|Rand\([^)]*\)|[A-Za-z][A-Za-z0-9]*(?:\[[^\]]*\])?)/g;

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

  return blocks
    .map((raw) => {
      const separator = raw.indexOf(":");
      if (separator <= 0) return null;
      return {
        name: raw.slice(0, separator).trim(),
        value: raw
          .slice(separator + 1)
          .replace(/\r?\n[ \t]+/g, " ")
          .trim(),
        raw
      };
    })
    .filter((header): header is HeaderBlock => header !== null);
}

function isTransportHeader(name: string): boolean {
  const normalized = name.toLowerCase();
  return transportHeaders.has(normalized) || transportHeaderPattern.test(normalized);
}

function auditCategory(name: string): AuditItem["category"] {
  const normalized = name.toLowerCase();
  if (transportHeaders.has(normalized)) return transportHeaders.get(normalized)!;
  if (/auth|dkim|dmarc|spf/i.test(normalized)) return "authentication";
  if (/delivery|return-path|delivered|complaint/i.test(normalized)) return "delivery";
  if (/^received|relay|route|transport|queue|mta/i.test(normalized)) return "routing";
  return "metadata";
}

function addReplacement(
  replacements: Map<string, Replacement>,
  value: string | undefined,
  tag: string,
  source: string
) {
  const trimmed = value?.trim();
  if (!trimmed || trimmed.length < 2 || /^__/.test(trimmed)) return;
  const key = trimmed.toLowerCase();
  if (!replacements.has(key)) {
    replacements.set(key, { value: trimmed, tag, source });
  }
}

function parseAddress(value: string): { displayName: string; email: string } | null {
  const match = value.match(/(?:^|<)([^<>\s]+@[^<>\s]+)(?:>|$)/);
  if (!match) return null;
  const email = match[1].replace(/^mailto:/i, "");
  const displayName = value
    .replace(match[0], "")
    .replace(/^[\s"'<>]+|[\s"'<>]+$/g, "")
    .trim();
  return { displayName, email };
}

function deriveReplacements(
  headers: HeaderBlock[],
  allHeaders: HeaderBlock[]
): Replacement[] {
  const map = new Map<string, Replacement>();
  const first = (name: string) => headers.find((header) => header.name.toLowerCase() === name);
  const from = first("from");
  const to = first("to");
  const replyTo = first("reply-to");
  const returnPath = allHeaders.find((header) => header.name.toLowerCase() === "return-path");

  if (from) {
    const address = parseAddress(from.value);
    if (address) {
      addReplacement(map, address.email, "__From_email", "From header");
      addReplacement(map, address.displayName, "__From_nm", "From header");
      const domain = address.email.split("@")[1];
      addReplacement(map, domain, "__MainDomainName", "From address domain");
    }
  }

  if (to) {
    const address = parseAddress(to.value);
    if (address) {
      addReplacement(map, address.email, "__ToE", "To header");
      addReplacement(map, address.email.split("@")[0], "__ToU", "To address");
      addReplacement(map, address.email.split("@")[1], "user_dom", "To address domain");
    }
  }

  if (replyTo) {
    const address = parseAddress(replyTo.value);
    if (address) addReplacement(map, address.email, "__Reply-To", "Reply-To header");
  }

  if (returnPath) {
    const address = parseAddress(returnPath.value);
    if (address) {
      addReplacement(map, address.email, "__Returnpath", "Return-Path transport header");
      addReplacement(map, address.email.split("@")[1], "__Bounce_dn", "Return-Path domain");
    }
  }

  for (const received of allHeaders.filter((header) => header.name.toLowerCase() === "received")) {
    const ip = received.value.match(/\[([0-9a-f:.]+)\]/i)?.[1];
    const host = received.value.match(/\bfrom\s+([a-z0-9.-]+\.[a-z]{2,})\b/i)?.[1];
    addReplacement(map, ip, "__Ip", "Received routing header");
    addReplacement(map, host, "__rDNS", "Received routing header");
  }

  return [...map.values()].sort((a, b) => b.value.length - a.value.length);
}

function applyReplacements(template: string, replacements: Replacement[]): string {
  return replacements.reduce((result, replacement) => {
    const escaped = replacement.value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const isEmailOrDomain = /[@.]/.test(replacement.value);
    const boundary = isEmailOrDomain ? "(?<![\\w.+-])" : "(?<![\\w])";
    const endBoundary = isEmailOrDomain ? "(?![\\w.+-])" : "(?![\\w])";
    return result.replace(new RegExp(`${boundary}${escaped}${endBoundary}`, "gi"), replacement.tag);
  }, template);
}

export function analyzeEmail(raw: string): EmailAnalysis {
  const normalized = raw.replace(/\r\n/g, "\n");
  const separator = normalized.indexOf("\n\n");
  if (separator < 0) {
    const detectedTags = [...new Set(normalized.match(tagPattern) ?? [])];
    return {
      cleanedTemplate: applyReplacements(normalized, []),
      audit: [],
      replacements: [],
      detectedTags,
      headerCount: 0
    };
  }

  const rawHeaders = normalized.slice(0, separator);
  const body = normalized.slice(separator + 2);
  const allHeaders = splitHeaderBlocks(rawHeaders);
  const audit = allHeaders
    .filter((header) => isTransportHeader(header.name))
    .map((header) => ({
      name: header.name,
      value: header.value,
      category: auditCategory(header.name)
    }));
  const templateHeaders = allHeaders.filter((header) => !isTransportHeader(header.name));
  const replacements = deriveReplacements(templateHeaders, allHeaders);
  const taggedHeaders = allHeaders.flatMap((header) => {
    const name = header.name.toLowerCase();
    if (isTransportHeader(header.name) && name !== "return-path") return [];
    if (name === "return-path") return [`${header.name}: __Returnpath`];
    const headerTags: Record<string, string> = {
      from: "__From",
      to: "__To",
      subject: "__Subject",
      "reply-to": "__Reply-To",
      "return-path": "__Returnpath"
    };
    const tag = headerTags[name];
    return [tag ? `${header.name}: ${tag}` : header.raw];
  });
  const cleanBody = applyReplacements(body, replacements);
  const cleanedTemplate = `${taggedHeaders.join("\n")}\n\n${cleanBody}`;
  const detectedTags = [...new Set(cleanedTemplate.match(tagPattern) ?? [])];

  return {
    cleanedTemplate,
    audit,
    replacements,
    detectedTags,
    headerCount: allHeaders.length
  };
}

export function makeContactMatrix(usernames: string[], domains: string[]): string[] {
  return usernames.flatMap((username) =>
    domains.map((domain) => `${username.trim()}@${domain.trim()}`)
  );
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}
