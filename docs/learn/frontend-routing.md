# Frontend routing

SENTINEL uses React Router 6 with browser-history URLs. The application shell
owns branding, readiness state, primary navigation, breadcrumbs, and
analysis-specific navigation. Route matching is centralized in `src/routes.ts`;
the selected route renders its own content while existing API-backed panels
remain responsible for their data and interactions.

## URL map

| URL | Screen |
| --- | --- |
| `/` | Overview |
| `/upload` | PCAP upload |
| `/analyses` | Analysis history |
| `/analyses/:analysisId` | Analysis details |
| `/analyses/:analysisId/packets` | Packet metadata |
| `/analyses/:analysisId/flows` | Network flows |
| `/analyses/:analysisId/rules` | Rule findings |
| `/analyses/:analysisId/ml` | ML inference |
| `/analyses/:analysisId/hybrid` | Hybrid assessment |
| `/analyses/:analysisId/pipeline` | Pipeline execution and status |
| `/analyses/:analysisId/analytics` | Traffic analytics |
| `/events` | Security event feed |
| `/events/:eventId` | Event details and evidence |
| `/compare` | Analysis comparison |

Internal navigation uses router links, so browser Back and Forward and direct
deep links preserve the address bar and avoid full-document reloads. Analysis
routes validate positive integer IDs and load the referenced analysis before
showing its data. An unavailable record displays an error and a link to
analysis history. Unknown paths show a dedicated not-found screen.

Vite's development server and the production static hosting configuration must
serve the SPA entry point for nested paths. The built client then resolves the
path and renders the matching screen. The frontend does not replace backend
authorization or record validation; all analysis and event details continue
to come from the corresponding API endpoints.
