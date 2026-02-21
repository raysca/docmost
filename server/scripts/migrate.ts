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
