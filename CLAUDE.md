# aicop

KI-gestütztes CLI-Tool das JavaScript/TypeScript Code auf Sicherheitslücken,
AI-Smells und Tech-Debt scannt. Antworte immer auf Deutsch.

## Monorepo Struktur
- packages/cli/ → CLI Tool (Hauptpaket)
- packages/vscode/ → VSCode Extension
- packages/website/ → Website

## Tech Stack
- TypeScript + Node.js 18+
- AST-Parsing: @typescript-eslint/typescript-estree
- Build: tsup
- CLI: Commander.js
- UI: Chalk, Ora, Boxen
- Config: cosmiconfig
- Tests: Vitest

## Befehle
- Tests: npx vitest
- Build: npx tsup
- CLI testen: node dist/index.js scan ./testprojekt

## Regeln (34 gesamt)
- Security: 14 Regeln (command-injection, code-injection, open-redirect,
  insecure-deserialization, xxe-injection, ...)
- AI-Smells: 11 Regeln
- Tech-Debt: 9 Regeln

## VibeScore™
- 0–100, gewichtete Penalties
- Default minSeverity: warn
- Überspringt *.min.js und Dateien >500KB

## Features
- npx Support
- VSCode Inline-Diagnostics + Status Bar VibeScore
- Badge Generator
- Fix-Prompt Generator (mit Clipboard)
- GitHub Action
- Reporter: HTML / JSON / Terminal
- Interactive Mode

## Wichtig
- Keine Änderungen an *.min.js Dateien
- Immer TypeScript, kein plain JavaScript
- Tests müssen nach Änderungen grün bleiben (aktuell 19/19)
- smpclans ist das Referenzprojekt (0 errors, 0 warnings, 100/100)
- die Website unter aicop/packages/website soll nicht aufs git gepushed werden, genau so wenig wie unrelevante Dateien wie claude test dateien oder so
