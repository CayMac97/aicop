<div align="center">

# 🛡️ AICop

### Deine KI hat Bugs geschrieben. AICop findet sie.

Erkennt Sicherheitslücken, KI-Code-Smells und Tech-Debt — **bevor** du in Production deployst.

[![npm version](https://img.shields.io/npm/v/aicop?color=blue)](https://www.npmjs.com/package/aicop)
[![npm downloads](https://img.shields.io/npm/dm/aicop?color=brightgreen)](https://www.npmjs.com/package/aicop)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](#-license)
[![Node](https://img.shields.io/badge/node-%E2%89%A520-blue)](#-install)

```bash
npm install -g aicop
aicop scan ./src
```

Funktioniert mit jedem JS/TS-Projekt. Kein Config nötig, um loszulegen.

</div>

---

## 📚 Inhaltsverzeichnis

- [🆚 AICop vs. Vibecop](#-aicop-vs-vibecop)
- [🤖 Agent- & IDE-Integration](#-agent--ide-integration-claude-code-cursor-etc)
- [⚡ Massive Monorepo-Unterstützung](#-massive-monorepo-unterstützung-neu-in-v120)
- [❓ Was AICop macht](#-was-es-macht)
- [📦 Installation](#-install)
- [🚀 Verwendung](#-usage)
- [📋 Alle Regeln](#-all-rules)
- [📊 AIScore](#-aiscore)
- [⚙️ Konfiguration](#-configuration)
- [🧪 Test-Datei-Verhalten](#-test-file-behaviour)
- [🔄 GitHub Actions](#-github-actions)
- [🧩 VS Code Extension](#-vs-code-extension)
- [📈 Baseline Tracking](#-baseline-tracking)
- [🗂️ Projektstruktur](#️-project-structure)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## 🆚 AICop vs. Vibecop

Mit Version **1.2.0** festigt AICop seine Position als hochspezialisiertes, ultraschnelles Analyse-Tool für KI-generierten JavaScript/TypeScript-Code. Während Vibecop als poliertes, polyglottes Production-Tool mit Python-Support und tiefer CI/CD-Integration glänzt, fokussiert sich AICop konsequent auf rohe AST-Analyse im JS/TS-Ökosystem (41+ Regeln), Cross-File-Injections, High-Performance-Monorepo-Scaling und automatisierte AI-Fix-Prompts.

### Feature- & Genauigkeits-Vergleich

| Metrik / Feature | 🅰️ aicop 1.2.0 (aktuell) | 🅱️ vibecop 0.4.3 |
|---|:---:|:---:|
| **Fokus** | JS/TS AST Deep-Scans, AI-Smells | Polyglot, CI-Pipeline, Production-Tooling |
| **Aktive Regeln (JS/TS)** | **41** | ~12 |
| Hardcoded Secrets | 🟢 ✓ | 🟢 ✓ |
| `eval()`-Nutzung | 🟢 ✓ | 🟢 ✓ |
| TODO-Stubs | 🟢 ✓ (2×) | 🟡 ✓ (1×) |
| Cross-File SQL-Injection | 🟢 ✓ | 🔴 ✗ |
| Transparenz (`--explain`) | 🟢 ✓ (Pattern + Confidence) | 🔴 ✗ |
| Scoring-System | 🟢 Absolut (`Math.floor`, ehrlich) | 🔴 ✗ |
| Test-File-Handling | 🟢 Konfigurierbare Overrides | 🔴 ✗ |
| Agent / MCP-Integration | 🟢 ✓ | 🟢 ✓ |
| CLI-Tools (Fix-Prompt, Baseline) | 🟢 ✓ | 🔴 ✗ |
| Sprachen | JS/TS | 🟢 JS/TS/Python |

### Wer sollte was nutzen?

> 🅱️ **Vibecop**, wenn du ein produktionsreifes, polyglottes Tool für breite Projekte mit nativer CI-Pipeline-Integration brauchst.
>
> 🅰️ **AICop**, wenn du dedizierten, extrem tiefen Fokus auf JS/TS-Security, Cross-File-Injections, KI-spezifische Code-Smells und blitzschnelle Monorepo-Scans willst.
>
> 🤝 **Beide kombinieren?** Unbedingt. Nutze AICop lokal oder via Agents für tiefe Architektur-Smell-Analyse und Vibecop in deiner CI/CD-Pipeline für breite Abdeckung.

---

## 🤖 Agent- & IDE-Integration (Claude Code, Cursor, etc.)

AICop ist darauf ausgelegt, nahtlos mit autonomen Coding-Agents und modernen KI-Workflows zusammenzuarbeiten.

### Model Context Protocol (MCP) Server

AICop bringt einen eingebauten MCP-Server mit, sodass Agents wie Claude Code, Cursor oder Windsurf den Scanner direkt ansprechen und Findings live fixen können.

```bash
# MCP-Server für deinen Agent starten
aicop mcp
```

Einmal verbunden, kann dein Agent AICop autonom aufrufen, um den Workspace zu scannen und Issues zu fixen, bevor er seine Aufgabe abschließt.

### Auto-Fix Prompts

Falls du kein MCP nutzt, kannst du deine KI trotzdem automatisch fixen lassen — per generiertem Prompt mit den exakten AST-Verstößen:

```bash
aicop fix-prompt ./src > fix-instructions.txt
```

Kopiere `fix-instructions.txt` in ChatGPT oder Claude. Die KI erhält den exakten Kontext und schreibt die Dateien um, um alle Security- und Smell-Issues sauber zu fixen.

---

## ⚡ Massive Monorepo-Unterstützung (New in v1.2.0)

Seit Version 1.2.0 nutzt AICop einen fortschrittlichen On-Demand-AST-Parser mit einem Per-Worker-LRU-Cache. Das garantiert einen **flachen O(1)-Speicherverbrauch** (~80 MB pro Worker-Thread) — unabhängig von der Projektgröße. Die Last wird mühelos auf alle verfügbaren CPU-Kerne verteilt, sodass tausende Dateien in Sekunden gescannt werden, ganz ohne Out-Of-Memory-Crashes.

---

## ❓ Was es macht

AICop parst jede `.ts`, `.tsx`, `.js`, `.jsx`-Datei in einen vollständigen AST und führt **41 Detection-Regeln** aus:

| Kategorie | Anzahl | Was erkannt wird |
|---|:---:|---|
| 🔒 **Security** | 23 | Hardcoded Secrets, SQL-/Command-/Prompt-Injection, XSS, `eval`, JWT ohne Expiry, CORS-Fehlkonfig., SSRF, Path Traversal, schwache Crypto, ReDoS, Prototype Pollution, fehlende Rate Limits, Open Redirect, unsichere Deserialisierung, XXE-Injection, Next.js-Input-Validierung, fehlender CSRF-Schutz, unsichere Sessions, NoSQL-Injection |
| 🤖 **AI Smells** | 12 | Halluzinierte APIs, Next.js Client/Server-Konfusion, Dead Code, TODO-Stubs, Copy-Paste-Patterns, Debug-Reste, gemischte Async-Patterns, fehlende Null-Checks, generische Variablennamen, Magic Numbers, inkonsistentes Error-Handling, AI-Confidence-Score |
| 🧹 **Tech Debt** | 6 | Zyklomatische Komplexität, Funktionslänge, Nesting-Tiefe, God Files, hardcoded Config, fehlende Types |

Jede gescannte Datei bekommt einen **AI Confidence Score**, und jeder Scan erzeugt einen Gesamt-**AIScore™** (0–100).

---

## 📦 Install

```bash
npm install -g aicop      # globale Installation
npx aicop scan ./src      # einmalig, ohne Installation
pnpm dlx aicop scan ./src # via pnpm
```

> Benötigt **Node.js ≥ 20**.

---

## 🚀 Usage

```bash
aicop scan ./src                      # Verzeichnis scannen
aicop scan ./src --severity error     # nur Errors
aicop scan ./src --format html        # HTML-Report
aicop scan ./src --output report.html # in Datei speichern
aicop diff main                       # nur Dateien, die sich seit Branch `main` geändert haben
aicop scan ./src --ci                 # CI-Modus (exit 1 bei jedem Error)
aicop baseline save                   # aktuellen Score als Baseline speichern
aicop rules                           # alle verfügbaren Regeln auflisten
aicop init                            # .aicoprc.json Config erstellen
```

### CLI-Optionen

| Flag | Default | Beschreibung |
|---|---|---|
| `--severity` | `info` | Minimale Severity: `error`, `warn`, `info` |
| `--format` | `terminal` | Output-Format: `terminal`, `html`, `json` |
| `--output` | — | Report in eine Datei schreiben |
| `--ci` | — | Keine Farben, exit 1 bei jedem Error-Finding |
| `--rule` | — | Nur eine bestimmte Rule-ID ausführen |
| `--ignore` | — | Zusätzliche Glob-Patterns zum Ausschließen |
| `--config` | — | Pfad zu einer custom Config-Datei |

---

## 📋 All Rules

### 🔒 Security Rules

| Rule ID | Severity | Was erkannt wird |
|---|:---:|---|
| `security/hardcoded-secrets` | 🔴 error | Passwörter, Tokens, API-Keys im Code |
| `security/sql-injection` | 🔴 error | String-verkettete SQL-Queries |
| `security/nosql-injection` | 🔴 error | MongoDB-Queries aus ungesäubertem `req.body`, `req.query`, `req.params` |
| `security/xss-vulnerabilities` | 🔴 error | Ungesäubertes `innerHTML`, `document.write`, React `dangerouslySetInnerHTML` |
| `security/eval-usage` | 🔴 error | Direkte `eval()`-Aufrufe mit nicht-literalen Argumenten |
| `security/code-injection` | 🔴 error | `vm.runInNewContext`, `vm.runInThisContext`, `math.eval`/`mathjs.evaluate` mit dynamischem Input |
| `security/command-injection` | 🔴 error | `exec`, `execSync`, `spawn` mit string-verketteten Argumenten |
| `security/jwt-no-expiry` | 🔴 error | JWTs ohne `expiresIn`-Option signiert |
| `security/cors-misconfiguration` | 🟡 warn | `origin: '*'` oder `origin: true` auf authentifizierter Route |
| `security/ssrf-risk` | 🟡 warn | HTTP-Requests aus nutzergesteuerten URLs |
| `security/path-traversal` | 🔴 error | `fs`-Aufrufe mit ungesäubertem User-Input im Pfad |
| `security/weak-crypto` | 🟡 warn | MD5, SHA1, DES, RC4 |
| `security/regex-dos` | 🟡 warn | Regex anfällig für katastrophales Backtracking (ReDoS) |
| `security/prototype-pollution` | 🔴 error | Unsicheres `Object.assign(obj, userInput)`, `merge()` mit untrusted Data |
| `security/missing-rate-limit` | 🟡 warn | Express-Auth-Routen (`/login`, `/register`, …) ohne Rate-Limit-Middleware |
| `security/open-redirect` | 🟡 warn | `res.redirect()` mit unvalidiertem User-Input |
| `security/insecure-deserialization` | 🔴 error | `JSON.parse`, `eval`, `serialize-javascript` auf untrusted Input ohne Validierung |
| `security/xxe-injection` | 🔴 error | XML-Parser mit aktivierter External-Entity-Verarbeitung |
| `security/prompt-injection` | 🔴 error | Ungefilterter User-Input direkt an AI-SDKs |
| `security/nextjs-missing-input-validation` | 🟡 warn | Server Actions & Route Handlers sollten Input via Schema-Lib (z. B. Zod) validieren |

### 🤖 AI Smell Rules

| Rule ID | Severity | Was erkannt wird |
|---|:---:|---|
| `ai-smell/hallucinated-api-calls` | 🔴 error | Aufrufe von npm-Paketen, die nicht existieren |
| `ai-smell/nextjs-client-server-confusion` | 🟡 warn | Client-Hooks/Browser-Globals in Next.js-Dateien ohne `"use client"` |
| `ai-smell/dead-code-blocks` | 🟡 warn | Nicht erreichbarer Code nach `return`/`throw`/`break` |
| `ai-smell/todo-stub-functions` | 🟡 warn | Funktionen, deren Body nur ein TODO-Kommentar ist oder `"Not implemented"` wirft |
| `ai-smell/copy-paste-patterns` | 🟡 warn | Identische/nahezu identische Code-Blöcke (strukturelle Duplikation) |
| `ai-smell/debug-leftovers` | 🟡 warn | `console.log`, `debugger`, `console.debug` in Nicht-Testcode |
| `ai-smell/mixed-async-patterns` | 🟡 warn | Mischung aus `async/await` und `.then()/.catch()` in derselben Funktion |
| `ai-smell/missing-null-checks` | 🟡 warn | Zugriff auf nullable Werte ohne Guard |
| `ai-smell/generic-variable-names` | ⚪ info | Einzelbuchstaben- oder generische Namen (`data`, `temp`, `obj`, `result`) |
| `ai-smell/magic-numbers` | ⚪ info | Unerklärte numerische Literale (außer `0`, `1`, `-1`, `100`) |
| `ai-smell/inconsistent-error-handling` | 🟡 warn | Mischung aus `throw`, `return null`, `return { error }` in derselben Datei |
| `ai-smell/ai-confidence-scorer` | ⚪ info | Pro-Datei AI-Confidence-Score basierend auf akkumulierten Smell-Signalen |

### 🧹 Tech Debt Rules

| Rule ID | Severity | Was erkannt wird |
|---|:---:|---|
| `tech-debt/cyclomatic-complexity` | 🟡 warn | Funktionen mit zyklomatischer Komplexität > 10 |
| `tech-debt/function-length` | 🟡 warn | Funktionen länger als 60 Zeilen |
| `tech-debt/nesting-depth` | 🟡 warn | Code tiefer als 4 Ebenen verschachtelt |
| `tech-debt/god-files` | 🟡 warn | Dateien mit mehr als 500 Zeilen Code |
| `tech-debt/hardcoded-config` | ⚪ info | Magic Strings, die wie Env-Config aussehen (URLs, Ports, Hostnames) |
| `tech-debt/missing-types` | ⚪ info | TypeScript `any`, ungetypte Parameter oder Rückgabewerte |

---

## 📊 AIScore

Der **AIScore™** ist eine Zahl von 0–100, die das gesamte AI-Smell- und Security-Risiko deiner Codebase zusammenfasst.

| Score | Label | Bedeutung |
|:---:|---|---|
| 0–20 | 🟢 Clean | Sehr wenige Issues |
| 21–50 | 🟡 AI-touched | Einige Smells, Review empfohlen |
| 51–80 | 🟠 Heavy AI smell | Signifikanter Rework nötig |
| 81–100 | 🔴 Needs rewrite | Größere Security- oder Qualitätsprobleme |

> Der AIScore berücksichtigt nur `error`- und `warn`-Findings. `info`-Findings beeinflussen ihn nicht.

---

## ⚙️ Configuration

```bash
aicop init   # erstellt .aicoprc.json im Projekt-Root
```

```json
{
  "include": ["src/**/*.{ts,tsx,js,jsx}"],
  "exclude": ["node_modules", "dist", "build", "**/*.test.*"],
  "rules": {
    "security/hardcoded-secrets": "error",
    "ai-smell/magic-numbers": "off",
    "tech-debt/missing-types": "warn"
  },
  "thresholds": {
    "maxErrors": 0,
    "maxWarnings": 10,
    "minAIScore": 60
  }
}
```

Alle Regel-Severities können auf `"error"`, `"warn"`, `"info"` oder `"off"` gesetzt werden.

> Dateien größer als 500 KB werden automatisch übersprungen. Minifizierte Dateien (`*.min.js`, `*.min.css`), Chunk-Dateien und Vendor-Verzeichnisse sind standardmäßig ausgeschlossen.

---

## 🧪 Test-File Behaviour

AICop wendet auf Testdateien (Pfade mit `test/`, `tests/`, `spec/`, `__tests__/`, oder Dateinamen wie `.test.ts`, `.spec.js`) gelockerte Regeln an:

| Regel | Normale Dateien | Testdateien |
|---|---|---|
| `security/hardcoded-secrets` | 🔴 ERROR | 🟡 WARN — *„hardcoded secret in test file — use environment variables even in tests"* |
| `security/missing-rate-limit` | ✅ geprüft | ⏭️ komplett übersprungen |

---

## 🔄 GitHub Actions

```yaml
# .github/workflows/aicop.yml
name: AICop
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - uses: aicop/action@v1
        with:
          path: ./src
          severity: warn
```

Oder inline, ohne die Action:

```yaml
- run: npx aicop scan ./src --ci --severity warn
```

---

## 🧩 VS Code Extension

Die **AICop VS Code Extension** (`packages/vscode-extension`) bringt Echtzeit-Diagnostik direkt in deinen Editor:

- ✏️ Unterstreicht Findings inline beim Tippen
- 🚦 Zeigt Severity-Icons (🔴 error / ⚠️ warn / ℹ️ info) im Problems-Panel
- 🔍 Fügt CodeLens über geflaggten Funktionen mit Quick-Fix-Link hinzu
- 📊 Statusleiste zeigt den AIScore der aktuellen Datei
- ⌨️ Befehle: `AICop: Scan Current File`, `AICop: Scan Entire Workspace`, `AICop: Clear All Diagnostics`

Lokale Installation:

```bash
npm run package:extension    # baut eine .vsix-Datei
code --install-extension aicop-1.0.0.vsix
```

---

## 📈 Baseline Tracking

Verfolge deinen Codebase-Score über die Zeit:

```bash
aicop baseline save         # speichert aktuellen AIScore als Baseline
# ... Dinge fixen ...
aicop scan ./src            # Output zeigt Delta zur Baseline (↑ oder ↓)
```

Die Baseline wird in `.aicop-baseline.json` gespeichert (in Git einchecken, um sie im Team zu teilen).

---

## 🗂️ Project Structure

```
aicop.net/
├── packages/
│   ├── cli/                   # Haupt-CLI-Paket (auf npm als "aicop" veröffentlicht)
│   │   ├── src/
│   │   │   ├── scanner/       # AST-Walker + 35 Detection-Regeln
│   │   │   │   └── rules/
│   │   │   │       ├── security/    # 15 Security-Regeln
│   │   │   │       ├── ai-smells/   # 11 AI-Smell-Regeln
│   │   │   │       └── tech-debt/   # 6 Tech-Debt-Regeln
│   │   │   ├── reporter/      # Terminal-, HTML- und JSON-Reporter
│   │   │   ├── diff/          # Git-Diff-Integration
│   │   │   ├── fix-prompt/    # AI-Fix-Suggestion-Engine
│   │   │   └── config/        # Config-Loading und Defaults
│   │   └── tests/             # Smoke-Tests + Flagging-Fixtures
│   ├── vscode-extension/      # VS Code Extension
│   └── website/               # aicop.net Landing Page
└── action.yml                 # GitHub-Action-Definition
```

---

## 🤝 Contributing

1. Repo forken
2. `npm install` im Root (nutzt npm Workspaces)
3. `npm run build`, um die CLI zu kompilieren
4. `npm test`, um die 19 Smoke-Tests laufen zu lassen
5. Deine Regel in `packages/cli/src/scanner/rules/<category>/your-rule.ts` hinzufügen
6. In `packages/cli/src/scanner/rules/index.ts` registrieren
7. Test-Fixture in `packages/cli/tests/fixtures/` hinzufügen
8. Pull Request öffnen

---

## 📄 License

**MIT** — für immer kostenlos. Dein Code verlässt niemals deine Maschine.

<div align="center">

---

Made with 🛡️ for the AI-generated code era

</div>
