import { Hono } from "hono";
import { bearerAuth, type ResourceEnv, type Verifier } from "./bearer.js";
import { notesRoutes } from "./notes.js";
import { NoteStore } from "./store.js";

export function createResourceRouter(deps: {
  verifyAccessToken: Verifier;
}): Hono {
  const router = new Hono<ResourceEnv>();
  const store = new NoteStore();
  router.use("/notes/*", bearerAuth(deps.verifyAccessToken));
  router.use("/notes", bearerAuth(deps.verifyAccessToken));
  router.route("/notes", notesRoutes(store));
  router.onError((_err, c) => {
    // Deliberately do not log the error: it may carry token material.
    return c.json({ error: "internal_error" }, 500);
  });
  router.notFound((c) => c.json({ error: "not_found" }, 404));
  return router as unknown as Hono;
}
