import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import App from "./App";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("SENTINEL foundation", () => {
  it("shows an online API status after a successful health check", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response('{"status":"ok"}')),
    );

    render(<App />);

    expect(await screen.findByRole("status")).toHaveTextContent("API online");
    expect(
      screen.getByRole("heading", { name: /see what is happening/i }),
    ).toBeInTheDocument();
  });

  it("shows an unavailable status when the API cannot be reached", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("connection refused")),
    );

    render(<App />);

    expect(await screen.findByRole("status")).toHaveTextContent(
      "API unavailable",
    );
  });
});
