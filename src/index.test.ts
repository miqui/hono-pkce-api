import { describe, expect, it } from "vitest";
import { app } from "./index.js";

describe("/healthz", () => {
  it("returns ok", async () => {
    const res = await app.request("/healthz");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok" });
  });
});
