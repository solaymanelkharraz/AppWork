# Mailroom Template Lab

A browser-based email source sanitizer and deliverability notes workspace built with Next.js App Router, TypeScript, and Tailwind CSS.

## Getting started

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

## Features

- Parse RFC 5322 headers, retain message/template headers, and extract transport, delivery, and authentication metadata into an audit view.
- Infer reverse tags for sender, recipient, reply-to, subject, and observed routing values. Mapping is deterministic and based only on values found in the supplied message.
- Inspect and filter extracted headers, copy or download the recovered template, and import `.eml` or text sources.
- Keep operational notes, maintain a local readiness checklist, and generate the 2-user × 4-domain contact matrix.

The parser and ledger run in the browser. Notes, checklist status, and contact inputs are saved to local browser storage and are not synchronized to a server.

## Validation

```bash
npm run typecheck
npm run build
```
