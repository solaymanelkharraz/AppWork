# Mailroom Floor Utilities

A browser-based email source sanitizer and 8-contact matrix generator built with Next.js App Router, TypeScript, and Tailwind CSS.

## Getting started

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

## Features

- Remove post-send transport, routing, delivery, and authentication headers into a dedicated `Stripped Elements` audit list.
- Drop common webmail delivery wrappers (`Created at`, delivery duration, SPF/DKIM/DMARC status, and export controls) from the recovered source while retaining them in the audit list.
- Replace static timestamps in retained headers and split HTML content into independently viewable and copyable Header, Body, and Footer sections.
- Map known sender, recipient, bounce, and unsubscribe-link domains and recipient/tracking identifiers where their values are present in the source.
- Recover template header tokens and map values inferred from sender, recipient, return-path, and observed routing headers.
- Recognize the supported random, date, dynamic, user, domain, infrastructure, and header tag forms listed in `TAG_DICTIONARY` in `lib/email-engine.ts`.
- Cross-multiply two usernames and four domains, de-duplicate the eight contact combinations, and copy the result in one action.

The utilities run in the browser. Email source is not uploaded or synchronized. Values that cannot be inferred from the source remain unchanged rather than being guessed.

## Validation

```bash
npm run typecheck
npm run build
```
