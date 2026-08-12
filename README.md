# Red Hat OpenShift - CVE Viewer

Minimal web app that helps OpenShift users see which CVEs were fixed in releases **newer** than their current cluster version.

Select a channel type, channel, and version. The app collects RHSA advisories from later versions in that channel and lists the related CVEs (description, severity, dates, and fixed-in version).

## Stack

- [React](https://react.dev/) 18
- [Vite](https://vitejs.dev/) 6
- [PatternFly](https://www.patternfly.org/) 6 (`react-core`, `react-table`, `react-icons`)

Frontend only — the browser calls public APIs directly (no backend).

## Features

- Channel type filter: `candidate`, `fast`, `stable`, `eus`
- Searchable typeahead selects for channel type, channel, and version
- Full channel list from the Cincinnati graph-data repository
- RHSA-focused CVE table with links to Red Hat Security
- Text filter across table columns
- Multi-select severity filter (checkboxes)
- Sortable columns and pagination
- Light / dark theme toggle (dark by default)

## Requirements

- Node.js 18+ (recommended)
- Network access to the APIs listed below (CORS is handled by those services)

## Quick start

```bash
npm install
npm run dev
```

Open the URL printed by Vite (usually `http://localhost:5173`).

### Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start the Vite development server |
| `npm run build` | Production build into `dist/` |
| `npm run preview` | Serve the production build locally |

## How it works

1. **Channels** — Loaded from the GitHub Contents API for [`openshift/cincinnati-graph-data`](https://github.com/openshift/cincinnati-graph-data) (`channels/*.yaml`), filtered to `candidate` / `fast` / `stable` / `eus`.
2. **Versions** — Loaded from the OpenShift upgrade graph for the selected channel.
3. **RHSAs** — Extracted from `metadata.url` on graph nodes newer than the selected version.
4. **CVEs** — Resolved via the Red Hat Security Data API (`csaf.json` + `cve.json`), batched and paginated.

### APIs

| Purpose | Endpoint |
|---------|----------|
| Channel list | `https://api.github.com/repos/openshift/cincinnati-graph-data/contents/channels` |
| Versions / upgrade graph | `https://api.openshift.com/api/upgrades_info/v1/graph?channel=<channel>` |
| RHSA / CVE data | `https://access.redhat.com/hydra/rest/securitydata` |

Security Data API documentation: [Red Hat Security Data API](https://docs.redhat.com/en/documentation/red_hat_security_data_api/1.0/html-single/red_hat_security_data_api/index).

## Project layout

```
.
├── index.html          # App shell (dark theme class by default)
├── package.json
├── vite.config.js      # Single-bundle oriented build
├── src/
│   ├── main.jsx        # React entry + PatternFly base CSS
│   └── App.jsx         # UI and data fetching
└── .cursor/rules/      # Agent / project conventions
```

The UI is intentionally concentrated in `App.jsx`, composing PatternFly 6 components inline (no custom component library).

## Notes

- GitHub API unauthenticated rate limits may apply when loading channels (60 requests/hour per IP). Prefer reusing a warm session rather than hard-refreshing repeatedly during development.
- CVE loading can take a few seconds for channels with many RHSA advisories because several Security Data requests are issued in batches.
- Production build is configured to avoid unnecessary code splitting (`manualChunks: undefined`) so the output stays small.

## License

Private project (`"private": true` in `package.json`). Add a license file if you plan to distribute it.
