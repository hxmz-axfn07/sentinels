import { matchRoutes, type RouteObject } from "react-router-dom";

export type PageKey =
  | "overview"
  | "upload"
  | "analyses"
  | "analysis"
  | "packets"
  | "flows"
  | "rules"
  | "ml"
  | "hybrid"
  | "pipeline"
  | "analytics"
  | "events"
  | "event"
  | "compare"
  | "not-found";

export type AppRoute = {
  page: PageKey;
  title: string;
  path: string;
};

export const appRoutes: AppRoute[] = [
  { path: "/", page: "overview", title: "Overview" },
  { path: "/upload", page: "upload", title: "Upload" },
  { path: "/analyses", page: "analyses", title: "Analysis history" },
  {
    path: "/analyses/:analysisId",
    page: "analysis",
    title: "Analysis details",
  },
  {
    path: "/analyses/:analysisId/packets",
    page: "packets",
    title: "Packets",
  },
  { path: "/analyses/:analysisId/flows", page: "flows", title: "Flows" },
  {
    path: "/analyses/:analysisId/rules",
    page: "rules",
    title: "Rule detection",
  },
  { path: "/analyses/:analysisId/ml", page: "ml", title: "ML detection" },
  {
    path: "/analyses/:analysisId/hybrid",
    page: "hybrid",
    title: "Hybrid risk",
  },
  {
    path: "/analyses/:analysisId/pipeline",
    page: "pipeline",
    title: "Pipeline",
  },
  {
    path: "/analyses/:analysisId/analytics",
    page: "analytics",
    title: "Traffic analytics",
  },
  { path: "/events", page: "events", title: "Security events" },
  { path: "/events/:eventId", page: "event", title: "Event details" },
  { path: "/compare", page: "compare", title: "Analysis comparison" },
];

const routeObjects: RouteObject[] = [
  ...appRoutes.map(({ path, page, title }) => ({
    path,
    handle: { page, title },
  })),
  {
    path: "*",
    handle: { page: "not-found" as const, title: "Page not found" },
  },
];

export function resolveAppRoute(pathname: string): {
  page: PageKey;
  title: string;
  params: Record<string, string | undefined>;
} {
  const matches = matchRoutes(routeObjects, pathname);
  const match = matches?.at(-1);
  const handle = match?.route.handle as
    { page: PageKey; title: string } | undefined;
  return {
    page: handle?.page ?? "not-found",
    title: handle?.title ?? "Page not found",
    params: match?.params ?? {},
  };
}
