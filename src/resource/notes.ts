import { Hono, type Context } from "hono";
import { bodyLimit } from "hono/body-limit";
import { z } from "zod";
import { requireScope } from "./bearer.js";
import type { ResourceEnv } from "./types.js";
import type { Note, NoteStore } from "./store.js";

const noteSchema = z.object({
  title: z.string().min(1).max(200),
  body: z.string().max(10000),
});

const publicNote = (n: Note) => ({
  id: n.id,
  title: n.title,
  body: n.body,
  createdAt: n.createdAt,
  updatedAt: n.updatedAt,
});

export const MAX_NOTES_PER_OWNER = 100;

const limit = bodyLimit({
  maxSize: 32 * 1024,
  onError: (c) => c.json({ error: "payload_too_large" }, 413),
});

export function notesRoutes(store: NoteStore): Hono<ResourceEnv> {
  const app = new Hono<ResourceEnv>();
  const read = requireScope("notes:read");
  const write = requireScope("notes:write");
  const notFound = (c: Context<ResourceEnv>) =>
    c.json({ error: "not_found" }, 404);

  async function parse(req: Request) {
    let json: unknown;
    try {
      json = await req.json();
    } catch {
      return { error: "invalid_json" as const };
    }
    const r = noteSchema.safeParse(json);
    return r.success
      ? { data: r.data }
      : { error: "validation_error" as const, issues: r.error.issues.map((i) => ({ path: i.path, message: i.message })) };
  }

  app.get("/", read, (c) =>
    c.json({ notes: store.list(c.get("auth").sub).map(publicNote) }),
  );

  app.get("/:id", read, (c) => {
    const n = store.get(c.get("auth").sub, c.req.param("id"));
    return n ? c.json(publicNote(n)) : notFound(c);
  });

  app.post("/", write, limit, async (c) => {
    const p = await parse(c.req.raw);
    if ("error" in p) return c.json(p, 400);
    if (store.count(c.get("auth").sub) >= MAX_NOTES_PER_OWNER) {
      return c.json({ error: "quota_exceeded", max: MAX_NOTES_PER_OWNER }, 429);
    }
    return c.json(publicNote(store.create(c.get("auth").sub, p.data)), 201);
  });

  app.put("/:id", write, limit, async (c) => {
    const p = await parse(c.req.raw);
    if ("error" in p) return c.json(p, 400);
    const n = store.update(c.get("auth").sub, c.req.param("id"), p.data);
    return n ? c.json(publicNote(n)) : notFound(c);
  });

  app.delete("/:id", write, (c) =>
    store.delete(c.get("auth").sub, c.req.param("id"))
      ? c.body(null, 204)
      : notFound(c),
  );

  return app;
}
