import { randomUUID } from "node:crypto";

export interface Note {
  id: string;
  owner: string;
  title: string;
  body: string;
  createdAt: string;
  updatedAt: string;
}

export interface NoteInput {
  title: string;
  body: string;
}

export class NoteStore {
  private notes = new Map<string, Note>();

  list(owner: string): Note[] {
    return [...this.notes.values()].filter((n) => n.owner === owner);
  }

  count(owner: string): number {
    return this.list(owner).length;
  }

  get(owner: string, id: string): Note | undefined {
    const n = this.notes.get(id);
    return n && n.owner === owner ? n : undefined;
  }

  create(owner: string, input: NoteInput): Note {
    const now = new Date().toISOString();
    const note: Note = {
      id: randomUUID(),
      owner,
      ...input,
      createdAt: now,
      updatedAt: now,
    };
    this.notes.set(note.id, note);
    return note;
  }

  update(owner: string, id: string, input: NoteInput): Note | undefined {
    const n = this.get(owner, id);
    if (!n) return undefined;
    const updated = { ...n, ...input, updatedAt: new Date().toISOString() };
    this.notes.set(id, updated);
    return updated;
  }

  delete(owner: string, id: string): boolean {
    return this.get(owner, id) ? this.notes.delete(id) : false;
  }
}
