# Drizzle Native Migration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the hand-rolled `apply-migration.ts` script and `drizzle-kit migrate` CLI with Drizzle's built-in programmatic migrator (`drizzle-orm/bun-sqlite/migrator`), and remove the `@libsql/client` devDependency entirely.

**Architecture:** A new `scripts/migrate.ts` script imports `migrate` from `drizzle-orm/bun-sqlite/migrator` and the existing `db` instance, then calls `migrate(db, { migrationsFolder })`. The `db:migrate` npm script is updated to run this new file. The old `scripts/apply-migration.ts` is deleted. `@libsql/client` is removed from `devDependencies` since `drizzle-kit generate` only reads schema files and needs no live DB connection.

**Tech Stack:** Bun, `bun:sqlite` (built-in), `drizzle-orm/bun-sqlite/migrator`, Drizzle Kit (generate only)

---

### Task 1: Verify `drizzle-kit generate` works without `@libsql/client`

> Confirm the generate command only reads schema files (no live DB needed) so it's safe to remove the dep.

**Files:**
- Read: `server/package.json`
- Read: `server/drizzle.config.ts`

**Step 1: Run generate in dry-run / check mode**

```bash
cd server && bunx drizzle-kit generate --config drizzle.config.ts 2>&1 | head -20
```

Expected: Either "No schema changes" or it generates SQL — no connection error.

**Step 2: Note result**

If it succeeds without error → safe to remove `@libsql/client`. If it errors about a missing client, document what it says before proceeding.

---

### Task 2: Write the new `scripts/migrate.ts`

**Files:**
- Create: `server/scripts/migrate.ts`
- Delete: `server/scripts/apply-migration.ts`

**Step 1: Write the new migration script**

Create `server/scripts/migrate.ts` with this content:

```typescript
/**
 * Applies pending Drizzle migrations using the built-in bun-sqlite migrator.
 * Run with: bun run scripts/migrate.ts
 */
import { migrate } from 'drizzle-orm/bun-sqlite/migrator';
import { join } from 'node:path';
import { db } from '../src/database/db';

const migrationsFolder = join(import.meta.dir, '..', 'drizzle');

migrate(db, { migrationsFolder });

console.log('✓ Migrations applied successfully');
```

**Step 2: Run the new script to verify it works**

```bash
cd server && bun run scripts/migrate.ts
```

Expected output:
```
✓ Migrations applied successfully
```

If the DB already has migrations applied, Drizzle's migrator skips them — that's correct behaviour.

**Step 3: Verify the migrations table was used**

```bash
cd server && bun -e "
import { Database } from 'bun:sqlite';
const db = new Database('./data/docmost.db');
const rows = db.query('SELECT * FROM __drizzle_migrations').all();
console.log(JSON.stringify(rows, null, 2));
db.close();
"
```

Expected: At least one row in `__drizzle_migrations` with a `hash` and `created_at`.

---

### Task 3: Update `package.json` scripts

**Files:**
- Modify: `server/package.json`

**Step 1: Update the `db:migrate` script**

In `server/package.json`, change:

```json
"db:migrate": "bunx drizzle-kit migrate",
```

to:

```json
"db:migrate": "bun run scripts/migrate.ts",
```

**Step 2: Run the updated script via npm script**

```bash
cd server && bun run db:migrate
```

Expected:
```
✓ Migrations applied successfully
```

---

### Task 4: Remove `@libsql/client` from devDependencies

**Files:**
- Modify: `server/package.json`

**Step 1: Remove the dependency**

In `server/package.json`, remove this line from `devDependencies`:

```json
"@libsql/client": "^0.17.0",
```

**Step 2: Re-install to update lockfile**

```bash
cd server && bun install
```

Expected: No errors. `bun.lock` updated.

**Step 3: Verify `drizzle-kit generate` still works**

```bash
cd server && bun run db:generate 2>&1 | head -20
```

Expected: No error about missing `@libsql/client`.

**Step 4: Verify `db:migrate` still works**

```bash
cd server && bun run db:migrate
```

Expected:
```
✓ Migrations applied successfully
```

---

### Task 5: Delete the old migration script

**Files:**
- Delete: `server/scripts/apply-migration.ts`

**Step 1: Delete the file**

```bash
rm server/scripts/apply-migration.ts
```

**Step 2: Verify no references remain**

```bash
grep -r "apply-migration" server/ --include="*.ts" --include="*.json"
```

Expected: No output.

---

### Task 6: Commit

**Step 1: Stage changes**

```bash
cd server && git add package.json bun.lock scripts/migrate.ts
git rm scripts/apply-migration.ts
```

**Step 2: Commit**

```bash
git commit -m "chore: replace custom migration script with drizzle-orm/bun-sqlite/migrator

- Add scripts/migrate.ts using migrate() from drizzle-orm/bun-sqlite/migrator
- Update db:migrate script to run new migrator
- Remove scripts/apply-migration.ts (hand-rolled runner, now redundant)
- Remove @libsql/client devDep (only needed for drizzle-kit migrate CLI)
"
```

---

## Verification Checklist

After all tasks are complete, confirm:

- [ ] `bun run db:generate` works (schema → SQL, no connection error)
- [ ] `bun run db:migrate` applies migrations via Drizzle's migrator
- [ ] `@libsql/client` is absent from `package.json` and `bun.lock`
- [ ] `scripts/apply-migration.ts` no longer exists
- [ ] `scripts/migrate.ts` exists and is importable without errors
- [ ] `__drizzle_migrations` table is populated in the SQLite DB
