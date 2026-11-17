import { describe, expect, it } from "vitest";
import { appRoutes, resolveAppRoute } from "./routes";

describe("application routes", () => {
  it.each([
    ["/", "overview"],
    ["/upload", "upload"],
    ["/analyses", "analyses"],
    ["/analyses/5", "analysis"],
    ["/analyses/5/packets", "packets"],
    ["/analyses/5/flows", "flows"],
    ["/analyses/5/rules", "rules"],
    ["/analyses/5/ml", "ml"],
    ["/analyses/5/hybrid", "hybrid"],
    ["/analyses/5/pipeline", "pipeline"],
    ["/analyses/5/analytics", "analytics"],
    ["/events", "events"],
    ["/events/rule_finding%3A5", "event"],
    ["/compare", "compare"],
    ["/incidents", "incidents"],
    ["/incidents/12", "incident"],
  ] as const)("matches %s to its own page", (path, page) => {
    expect(resolveAppRoute(path).page).toBe(page);
  });

  it("preserves route parameters and returns a not-found page", () => {
    expect(resolveAppRoute("/analyses/5/flows").params.analysisId).toBe("5");
    expect(resolveAppRoute("/events/rule_finding%3A5").params.eventId).toBe(
      "rule_finding:5",
    );
    expect(resolveAppRoute("/missing").page).toBe("not-found");
    expect(resolveAppRoute("/incidents/12").params.incidentId).toBe("12");
    expect(appRoutes).toHaveLength(16);
  });
});
