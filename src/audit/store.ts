import * as fs from 'fs';
import * as path from 'path';
import { AuditEntry } from '../flows/types';
import { HashedEntry, GENESIS_HASH, computeHash } from './chain';

export interface AuditStore {
  readonly path: string;
  append(entry: AuditEntry): void;
  all(): AuditEntry[];
  clear(): void;
}

/**
 * Append-only structured JSON audit log. One JSON object per line (JSONL).
 * Every entry from every actor/decision lands here.
 *
 * Tamper-evidence: `append` chains each entry to the previous one by computing
 * prevHash + hash (see chain.ts) BEFORE writing, so the log is a hash chain.
 */
export function createAuditStore(logFile?: string): AuditStore {
  const file = logFile ?? path.join(process.cwd(), 'data', 'audit.log.jsonl');
  fs.mkdirSync(path.dirname(file), { recursive: true });

  return {
    path: file,
    append(entry: AuditEntry) {
      const prevHash = readLastHash(file) ?? GENESIS_HASH;
      const hashed: HashedEntry = { ...entry, prevHash, hash: computeHash(prevHash, entry) };
      fs.appendFileSync(file, JSON.stringify(hashed) + '\n');
    },
    all(): AuditEntry[] {
      if (!fs.existsSync(file)) return [];
      const lines = fs
        .readFileSync(file, 'utf8')
        .split('\n')
        .filter((l) => l.trim().length > 0);
      return lines.map((l) => JSON.parse(l) as AuditEntry);
    },
    clear() {
      if (fs.existsSync(file)) fs.unlinkSync(file);
    },
  };
}

// Read just the last entry's hash (the chain tail) without parsing the whole file.
function readLastHash(file: string): string | null {
  if (!fs.existsSync(file)) return null;
  const lines = fs
    .readFileSync(file, 'utf8')
    .split('\n')
    .filter((l) => l.trim().length > 0);
  if (lines.length === 0) return null;
  const last = JSON.parse(lines[lines.length - 1]) as HashedEntry;
  return last.hash ?? null;
}
