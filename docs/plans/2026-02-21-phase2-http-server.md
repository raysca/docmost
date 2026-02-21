# Phase 2: HTTP Server & Routing Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the complete Hono HTTP server layer — entry point, middleware, singleton services, permission helpers, and all API route handlers — matching the existing NestJS reference server's API contract.

**Architecture:** Module-level singletons in `startup.ts` are imported directly by routes. Hono middleware handles auth (Better Auth session), workspace resolution (Host header), and error handling. Simple role-check helper functions replace CASL. Routes are thin: validate with Zod, check permissions, call service/repo, return JSON.

**Tech Stack:** Bun, Hono v4, drizzle-orm/bun-sqlite, Better Auth, Zod, @hono/zod-validator

---

### Task 1: Foundation — types, errors, permissions

**Files:**
- Create: `server/src/types.ts`
- Create: `server/src/lib/errors.ts`
- Create: `server/src/lib/permissions.ts`

**Step 1: Create `src/types.ts`** — Hono context variable map for full TypeScript inference

```typescript
// server/src/types.ts
import type { InferSelectModel } from 'drizzle-orm';
import type { users, workspaces } from './database/schema';

export type User = InferSelectModel<typeof users>;
export type Workspace = InferSelectModel<typeof workspaces>;

export type AppVariables = {
  user: User;
  workspace: Workspace;
};
```

**Step 2: Create `src/lib/errors.ts`**

```typescript
// server/src/lib/errors.ts
export class HttpError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = 'HttpError';
  }
}

export function notFound(msg = 'Not found'): never {
  throw new HttpError(404, msg);
}

export function forbidden(msg = 'Forbidden'): never {
  throw new HttpError(403, msg);
}

export function badRequest(msg = 'Bad request'): never {
  throw new HttpError(400, msg);
}

export function unauthorized(msg = 'Unauthorized'): never {
  throw new HttpError(401, msg);
}
```

**Step 3: Create `src/lib/permissions.ts`**

```typescript
// server/src/lib/permissions.ts

// Space roles: reader < writer < admin
const SPACE_ROLE_RANK: Record<string, number> = {
  reader: 1,
  writer: 2,
  admin: 3,
};

export function highestSpaceRole(roles: string[]): string {
  return roles.reduce((best, role) =>
    (SPACE_ROLE_RANK[role] ?? 0) > (SPACE_ROLE_RANK[best] ?? 0) ? role : best,
    'reader'
  );
}

export const canReadSpace     = (role: string) => ['reader', 'writer', 'admin'].includes(role);
export const canEditPage      = (role: string) => ['writer', 'admin'].includes(role);
export const canManagePage    = (role: string) => ['writer', 'admin'].includes(role);
export const canManageSpace   = (role: string) => role === 'admin';
export const canManageMembers = (role: string) => role === 'admin';
export const canManageShares  = (role: string) => ['writer', 'admin'].includes(role);

// Workspace roles: member < admin < owner
export const canManageWorkspace = (role: string) => ['owner', 'admin'].includes(role);
export const isWorkspaceOwner   = (role: string) => role === 'owner';
```

**Step 4: Verify TypeScript compiles**

```bash
cd server && bunx tsc --noEmit 2>&1 | head -20
```

Expected: no errors (or only pre-existing errors unrelated to new files).

**Step 5: Commit**

```bash
cd server && git add src/types.ts src/lib/errors.ts src/lib/permissions.ts
git commit -m "feat: add types, error helpers, and permission helpers"
```

---

### Task 2: Middleware

**Files:**
- Create: `server/src/middleware/error.middleware.ts`
- Create: `server/src/middleware/workspace.middleware.ts`
- Create: `server/src/middleware/auth.middleware.ts`

**Step 1: Create `src/middleware/error.middleware.ts`**

```typescript
// server/src/middleware/error.middleware.ts
import { createMiddleware } from 'hono/factory';
import { HttpError } from '../lib/errors';

export const errorMiddleware = createMiddleware(async (c, next) => {
  try {
    await next();
  } catch (err) {
    if (err instanceof HttpError) {
      return c.json({ error: err.message }, err.status as any);
    }
    console.error('[unhandled error]', err);
    return c.json({ error: 'Internal server error' }, 500);
  }
});
```

**Step 2: Create `src/middleware/workspace.middleware.ts`**

```typescript
// server/src/middleware/workspace.middleware.ts
import { createMiddleware } from 'hono/factory';
import type { AppVariables } from '../types';
import { workspaceRepo } from '../startup';

export const workspaceMiddleware = createMiddleware<{ Variables: AppVariables }>(async (c, next) => {
  const host = c.req.header('host') ?? '';
  const hostname = host.split(':')[0];

  let workspace = await workspaceRepo.findByHostname(hostname);
  if (!workspace) {
    // Dev fallback: use first workspace when host doesn't match
    workspace = await workspaceRepo.findFirst() ?? null;
  }

  if (!workspace) {
    return c.json({ error: 'Workspace not found' }, 404);
  }

  c.set('workspace', workspace);
  await next();
});
```

**Step 3: Create `src/middleware/auth.middleware.ts`**

Note: Better Auth is configured in Phase 3. For now, stub it to extract user from a header for development, and add a TODO to wire up Better Auth session.

```typescript
// server/src/middleware/auth.middleware.ts
import { createMiddleware } from 'hono/factory';
import type { AppVariables } from '../types';
import { userRepo } from '../startup';

export const authMiddleware = createMiddleware<{ Variables: AppVariables }>(async (c, next) => {
  // TODO(Phase 3): replace with Better Auth session validation
  // auth.api.getSession({ headers: c.req.raw.headers })
  const userId = c.req.header('x-user-id');
  if (!userId) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const workspace = c.get('workspace');
  const user = await userRepo.findById(userId, workspace.id);
  if (!user) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  c.set('user', user);
  await next();
});
```

**Step 4: Verify TypeScript compiles**

```bash
cd server && bunx tsc --noEmit 2>&1 | head -20
```

Expected: no new errors.

**Step 5: Commit**

```bash
cd server && git add src/middleware/
git commit -m "feat: add error, workspace, and auth middleware"
```

---

### Task 3: Startup singletons + app wiring

**Files:**
- Create: `server/src/startup.ts`
- Create: `server/src/app.ts`
- Create: `server/src/index.ts`

**Step 1: Create `src/startup.ts`**

```typescript
// server/src/startup.ts
import { db } from './database/db';
import {
  WorkspaceRepo,
  UserRepo,
  GroupRepo, GroupUserRepo,
  SpaceRepo, SpaceMemberRepo,
  PageRepo, PageHistoryRepo, BacklinkRepo,
  CommentRepo,
  AttachmentRepo,
  ShareRepo,
  NotificationRepo,
  WatcherRepo,
} from './database/repos';

// ── Repos ──────────────────────────────────────────────────────────────────
export const workspaceRepo    = new WorkspaceRepo(db);
export const userRepo         = new UserRepo(db);
export const groupRepo        = new GroupRepo(db);
export const groupUserRepo    = new GroupUserRepo(db);
export const spaceRepo        = new SpaceRepo(db);
export const spaceMemberRepo  = new SpaceMemberRepo(db);
export const pageRepo         = new PageRepo(db);
export const pageHistoryRepo  = new PageHistoryRepo(db);
export const backlinkRepo     = new BacklinkRepo(db);
export const commentRepo      = new CommentRepo(db);
export const attachmentRepo   = new AttachmentRepo(db);
export const shareRepo        = new ShareRepo(db);
export const notificationRepo = new NotificationRepo(db);
export const watcherRepo      = new WatcherRepo(db);
```

Note: Services will be added to `startup.ts` as they are created in later tasks.

**Step 2: Create `src/app.ts`**

```typescript
// server/src/app.ts
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import type { AppVariables } from './types';
import { errorMiddleware } from './middleware/error.middleware';
import { workspaceMiddleware } from './middleware/workspace.middleware';
import { authMiddleware } from './middleware/auth.middleware';

const app = new Hono<{ Variables: AppVariables }>();

// Global middleware
app.use('*', errorMiddleware);
app.use('*', logger());
app.use('/api/*', cors({
  origin: (origin) => origin, // reflect origin — tighten in production
  credentials: true,
}));

// Workspace resolution on all API routes
app.use('/api/*', workspaceMiddleware);

// Auth required on all API routes except /api/auth/*
app.use('/api/*', async (c, next) => {
  if (c.req.path.startsWith('/api/auth/')) return next();
  return authMiddleware(c, next);
});

// Health check (unauthenticated)
app.get('/healthz', (c) => c.json({ status: 'ok' }));

// TODO: mount route files here as they are created (Tasks 4–14)

export default app;
```

**Step 3: Create `src/index.ts`**

```typescript
// server/src/index.ts
import { migrate } from 'drizzle-orm/bun-sqlite/migrator';
import { join } from 'node:path';
import { db } from './database/db';
import app from './app';

// Run migrations on boot
migrate(db, { migrationsFolder: join(import.meta.dir, '..', 'drizzle') });

const port = Number(Bun.env.PORT ?? 3000);

console.log(`Server starting on port ${port}`);

export default {
  port,
  fetch: app.fetch,
};
```

**Step 4: Verify server starts**

```bash
cd server && bun run src/index.ts &
sleep 1
curl -s http://localhost:3000/healthz
kill %1
```

Expected: `{"status":"ok"}`

**Step 5: Commit**

```bash
cd server && git add src/startup.ts src/app.ts src/index.ts
git commit -m "feat: add startup singletons, Hono app, and Bun entry point"
```

---

### Task 4: Auth routes

**Files:**
- Create: `server/src/routes/auth.routes.ts`
- Modify: `server/src/app.ts`

**Step 1: Create `src/routes/auth.routes.ts`**

```typescript
// server/src/routes/auth.routes.ts
import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import type { AppVariables } from '../types';
import { workspaceRepo, userRepo } from '../startup';
import { badRequest, notFound } from '../lib/errors';

const auth = new Hono<{ Variables: AppVariables }>();

// POST /api/auth/setup — create first workspace + admin user
auth.post('/setup', zValidator('json', z.object({
  workspaceName: z.string().min(1),
  fullName: z.string().min(1),
  email: z.string().email(),
  password: z.string().min(8),
})), async (c) => {
  const count = await workspaceRepo.count();
  if (count > 0) return badRequest('Workspace already set up');

  const { workspaceName, fullName, email, password } = c.req.valid('json');

  const workspace = await workspaceRepo.insertWorkspace({
    name: workspaceName,
    hostname: workspaceName.toLowerCase().replace(/\s+/g, '-'),
  });

  const hashedPassword = await Bun.password.hash(password);
  const user = await userRepo.insertUser({
    name: fullName,
    email,
    password: hashedPassword,
    role: 'owner',
    workspaceId: workspace.id,
    emailVerifiedAt: new Date().toISOString(),
  });

  return c.json({ workspace, user });
});

// POST /api/auth/login
auth.post('/login', zValidator('json', z.object({
  email: z.string().email(),
  password: z.string().min(1),
})), async (c) => {
  const { email, password } = c.req.valid('json');
  const workspace = c.get('workspace');

  const user = await userRepo.findByEmail(email, workspace.id);
  if (!user || !user.password) return c.json({ error: 'Invalid credentials' }, 401);

  const valid = await Bun.password.verify(password, user.password);
  if (!valid) return c.json({ error: 'Invalid credentials' }, 401);

  await userRepo.updateLastLogin(user.id, workspace.id);

  // TODO(Phase 3): issue Better Auth session cookie
  // For now return user (Phase 3 will replace this with a session cookie)
  const { password: _, ...safeUser } = user;
  return c.json({ user: safeUser });
});

// POST /api/auth/logout
auth.post('/logout', async (c) => {
  // TODO(Phase 3): clear Better Auth session cookie
  return c.json({ success: true });
});

export default auth;
```

**Step 2: Mount auth routes in `src/app.ts`**

Add near the top of `app.ts` after the existing imports:
```typescript
import authRoutes from './routes/auth.routes';
```

Add before the `export default app` line:
```typescript
app.route('/api/auth', authRoutes);
```

**Step 3: Test setup endpoint**

```bash
cd server && bun run src/index.ts &
sleep 1
curl -s -X POST http://localhost:3000/api/auth/setup \
  -H "Content-Type: application/json" \
  -H "Host: localhost" \
  -d '{"workspaceName":"Test","fullName":"Admin","email":"admin@test.com","password":"password123"}' | jq .
kill %1
```

Expected: `{ "workspace": {...}, "user": {...} }` (no password field in user).

**Step 4: Commit**

```bash
cd server && git add src/routes/auth.routes.ts src/app.ts
git commit -m "feat: add auth routes (setup, login, logout)"
```

---

### Task 5: Workspace routes

**Files:**
- Create: `server/src/routes/workspaces.routes.ts`
- Modify: `server/src/app.ts`

**Step 1: Create `src/routes/workspaces.routes.ts`**

```typescript
// server/src/routes/workspaces.routes.ts
import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import type { AppVariables } from '../types';
import { workspaceRepo, userRepo } from '../startup';
import { forbidden, notFound, badRequest } from '../lib/errors';
import { canManageWorkspace } from '../lib/permissions';

const workspaces = new Hono<{ Variables: AppVariables }>();

// POST /api/workspace/public — no auth required
workspaces.post('/public', async (c) => {
  const workspace = c.get('workspace');
  const { name, logo, hostname, customDomain, allowedEmailDomains, defaultRole } = workspace;
  return c.json({ name, logo, hostname, customDomain, allowedEmailDomains, defaultRole });
});

// POST /api/workspace/info
workspaces.post('/info', async (c) => {
  const workspace = c.get('workspace');
  const activeUserCount = await workspaceRepo.getActiveUserCount(workspace.id);
  return c.json({ ...workspace, activeUserCount });
});

// POST /api/workspace/update
workspaces.post('/update', zValidator('json', z.object({
  name: z.string().min(1).optional(),
  logo: z.string().optional(),
  defaultRole: z.string().optional(),
  allowedEmailDomains: z.array(z.string()).optional(),
  enforceSso: z.boolean().optional(),
}).strict()), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  if (!canManageWorkspace(user.role ?? '')) forbidden();

  const updates = c.req.valid('json');
  const updated = await workspaceRepo.updateWorkspace(updates, workspace.id);
  return c.json(updated);
});

// POST /api/workspace/members
workspaces.post('/members', zValidator('json', z.object({
  limit: z.number().optional(),
  offset: z.number().optional(),
  query: z.string().optional(),
})), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  if (!canManageWorkspace(user.role ?? '')) forbidden();

  const pagination = c.req.valid('json');
  const result = await userRepo.getUsersPaginated(workspace.id, pagination);
  return c.json(result);
});

// POST /api/workspace/members/delete
workspaces.post('/members/delete', zValidator('json', z.object({
  userId: z.string(),
})), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  if (!canManageWorkspace(user.role ?? '')) forbidden();

  const { userId } = c.req.valid('json');
  await userRepo.softDeleteUser(userId, workspace.id);
  return c.json({ success: true });
});

// POST /api/workspace/members/change-role
workspaces.post('/members/change-role', zValidator('json', z.object({
  userId: z.string(),
  role: z.enum(['owner', 'admin', 'member']),
})), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  if (!canManageWorkspace(user.role ?? '')) forbidden();

  const { userId, role } = c.req.valid('json');
  const updated = await userRepo.updateUser({ role }, userId, workspace.id);
  if (!updated) notFound('User not found');
  return c.json(updated);
});

// POST /api/workspace/invites
workspaces.post('/invites', zValidator('json', z.object({
  limit: z.number().optional(),
  offset: z.number().optional(),
})), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  if (!canManageWorkspace(user.role ?? '')) forbidden();

  const invitations = await workspaceRepo.getPendingInvitations(workspace.id);
  return c.json(invitations);
});

// POST /api/workspace/invites/create
workspaces.post('/invites/create', zValidator('json', z.object({
  email: z.string().email(),
  role: z.enum(['admin', 'member']).optional(),
})), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  if (!canManageWorkspace(user.role ?? '')) forbidden();

  const { email, role = 'member' } = c.req.valid('json');

  const existing = await workspaceRepo.findInvitationByEmail(email, workspace.id);
  if (existing) return badRequest('Invitation already sent to this email');

  const token = Bun.randomUUIDv7();
  const invitation = await workspaceRepo.insertInvitation({
    email,
    role,
    token,
    workspaceId: workspace.id,
    invitedById: user.id,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
  });

  return c.json(invitation);
});

// POST /api/workspace/invites/revoke
workspaces.post('/invites/revoke', zValidator('json', z.object({
  invitationId: z.string(),
})), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  if (!canManageWorkspace(user.role ?? '')) forbidden();

  const { invitationId } = c.req.valid('json');
  await workspaceRepo.deleteInvitation(invitationId);
  return c.json({ success: true });
});

// POST /api/workspace/invites/accept (public)
workspaces.post('/invites/accept', zValidator('json', z.object({
  token: z.string(),
  name: z.string().optional(),
  password: z.string().min(8).optional(),
})), async (c) => {
  const workspace = c.get('workspace');
  const { token, name, password } = c.req.valid('json');

  const invitation = await workspaceRepo.findInvitationByToken(token);
  if (!invitation) notFound('Invitation not found');
  if (invitation.expiresAt && new Date(invitation.expiresAt) < new Date()) {
    return badRequest('Invitation has expired');
  }

  // Check if user already exists
  let user = await userRepo.findByEmail(invitation.email, workspace.id);
  if (!user) {
    const hashedPassword = password ? await Bun.password.hash(password) : null;
    user = await userRepo.insertUser({
      email: invitation.email,
      name: name ?? invitation.email.split('@')[0],
      password: hashedPassword,
      role: invitation.role ?? 'member',
      workspaceId: workspace.id,
      emailVerifiedAt: new Date().toISOString(),
      invitedById: invitation.invitedById,
    });
  }

  await workspaceRepo.deleteInvitation(invitation.id);
  return c.json({ success: true });
});

export default workspaces;
```

**Step 2: Mount in `app.ts`**

Add import:
```typescript
import workspaceRoutes from './routes/workspaces.routes';
```
Add mount:
```typescript
app.route('/api/workspace', workspaceRoutes);
```

**Step 3: Test public endpoint (no auth)**

```bash
cd server && bun run src/index.ts &
sleep 1
curl -s -X POST http://localhost:3000/api/workspace/public \
  -H "Host: localhost" | jq .
kill %1
```

Expected: workspace JSON with name, hostname fields.

**Step 4: Commit**

```bash
cd server && git add src/routes/workspaces.routes.ts src/app.ts
git commit -m "feat: add workspace routes"
```

---

### Task 6: User routes

**Files:**
- Create: `server/src/routes/users.routes.ts`
- Modify: `server/src/app.ts`

**Step 1: Create `src/routes/users.routes.ts`**

```typescript
// server/src/routes/users.routes.ts
import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import type { AppVariables } from '../types';
import { userRepo, workspaceRepo } from '../startup';
import { notFound } from '../lib/errors';

const users = new Hono<{ Variables: AppVariables }>();

// POST /api/users/me
users.post('/me', async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  const activeUserCount = await workspaceRepo.getActiveUserCount(workspace.id);
  const { password: _, ...safeUser } = user;
  return c.json({ user: safeUser, workspace: { ...workspace, activeUserCount } });
});

// POST /api/users/update
users.post('/update', zValidator('json', z.object({
  name: z.string().min(1).optional(),
  avatarUrl: z.string().optional(),
  locale: z.string().optional(),
  timezone: z.string().optional(),
  settings: z.record(z.unknown()).optional(),
}).strict()), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  const updates = c.req.valid('json');
  const updated = await userRepo.updateUser(updates, user.id, workspace.id);
  if (!updated) notFound('User not found');
  const { password: _, ...safeUser } = updated;
  return c.json(safeUser);
});

export default users;
```

**Step 2: Mount in `app.ts`**

```typescript
import userRoutes from './routes/users.routes';
// ...
app.route('/api/users', userRoutes);
```

**Step 3: Commit**

```bash
cd server && git add src/routes/users.routes.ts src/app.ts
git commit -m "feat: add user routes (me, update)"
```

---

### Task 7: Space routes

**Files:**
- Create: `server/src/routes/spaces.routes.ts`
- Modify: `server/src/app.ts`

**Step 1: Create `src/routes/spaces.routes.ts`**

```typescript
// server/src/routes/spaces.routes.ts
import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import type { AppVariables } from '../types';
import { spaceRepo, spaceMemberRepo } from '../startup';
import { forbidden, notFound, badRequest } from '../lib/errors';
import {
  canReadSpace, canManageSpace, canManageMembers, highestSpaceRole,
  canManageWorkspace,
} from '../lib/permissions';

const spaces = new Hono<{ Variables: AppVariables }>();

// POST /api/spaces/ — list user's spaces
spaces.post('/', zValidator('json', z.object({
  limit: z.number().optional(),
  offset: z.number().optional(),
  query: z.string().optional(),
}).optional().default({})), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  const pagination = c.req.valid('json');
  const result = await spaceMemberRepo.getUserSpaces(user.id, workspace.id, pagination);
  return c.json(result);
});

// POST /api/spaces/info
spaces.post('/info', zValidator('json', z.object({ spaceId: z.string() })), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  const { spaceId } = c.req.valid('json');

  const space = await spaceRepo.findById(spaceId, workspace.id);
  if (!space) notFound('Space not found');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, spaceId);
  const role = highestSpaceRole(roles);
  if (!canReadSpace(role)) forbidden();

  return c.json({ ...space, role });
});

// POST /api/spaces/create
spaces.post('/create', zValidator('json', z.object({
  name: z.string().min(1),
  slug: z.string().min(1).optional(),
  description: z.string().optional(),
  icon: z.string().optional(),
  visibility: z.enum(['public', 'private']).optional(),
})), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');

  const { name, slug, description, icon, visibility = 'private' } = c.req.valid('json');
  const spaceSlug = slug ?? name.toLowerCase().replace(/\s+/g, '-');

  const slugTaken = await spaceRepo.slugExists(spaceSlug, workspace.id);
  if (slugTaken) badRequest('Slug already in use');

  const space = await spaceRepo.insertSpace({
    name,
    slug: spaceSlug,
    description,
    icon,
    visibility,
    workspaceId: workspace.id,
    creatorId: user.id,
  });

  // Add creator as admin member
  await spaceMemberRepo.insertSpaceMember({
    spaceId: space.id,
    userId: user.id,
    role: 'admin',
    workspaceId: workspace.id,
  });

  return c.json(space);
});

// POST /api/spaces/update
spaces.post('/update', zValidator('json', z.object({
  spaceId: z.string(),
  name: z.string().min(1).optional(),
  description: z.string().optional(),
  icon: z.string().optional(),
  visibility: z.enum(['public', 'private']).optional(),
})), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  const { spaceId, ...updates } = c.req.valid('json');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, spaceId);
  if (!canManageSpace(highestSpaceRole(roles))) forbidden();

  const updated = await spaceRepo.updateSpace(updates, spaceId, workspace.id);
  if (!updated) notFound('Space not found');
  return c.json(updated);
});

// POST /api/spaces/delete
spaces.post('/delete', zValidator('json', z.object({ spaceId: z.string() })), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  const { spaceId } = c.req.valid('json');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, spaceId);
  if (!canManageSpace(highestSpaceRole(roles))) forbidden();

  await spaceRepo.deleteSpace(spaceId, workspace.id);
  return c.json({ success: true });
});

// POST /api/spaces/members
spaces.post('/members', zValidator('json', z.object({
  spaceId: z.string(),
  limit: z.number().optional(),
  offset: z.number().optional(),
})), async (c) => {
  const user = c.get('user');
  const { spaceId, ...pagination } = c.req.valid('json');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, spaceId);
  if (!canReadSpace(highestSpaceRole(roles))) forbidden();

  const result = await spaceMemberRepo.getSpaceMembersPaginated(spaceId, pagination);
  return c.json(result);
});

// POST /api/spaces/members/add
spaces.post('/members/add', zValidator('json', z.object({
  spaceId: z.string(),
  userIds: z.array(z.string()).optional(),
  groupIds: z.array(z.string()).optional(),
  role: z.enum(['reader', 'writer', 'admin']).optional().default('reader'),
})), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  const { spaceId, userIds = [], groupIds = [], role } = c.req.valid('json');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, spaceId);
  if (!canManageMembers(highestSpaceRole(roles))) forbidden();

  const inserts = [
    ...userIds.map(userId => spaceMemberRepo.insertSpaceMember({ spaceId, userId, role, workspaceId: workspace.id })),
    ...groupIds.map(groupId => spaceMemberRepo.insertSpaceMember({ spaceId, groupId, role, workspaceId: workspace.id })),
  ];
  await Promise.all(inserts);

  return c.json({ success: true });
});

// POST /api/spaces/members/remove
spaces.post('/members/remove', zValidator('json', z.object({
  memberId: z.string(),
  spaceId: z.string(),
})), async (c) => {
  const user = c.get('user');
  const { memberId, spaceId } = c.req.valid('json');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, spaceId);
  if (!canManageMembers(highestSpaceRole(roles))) forbidden();

  await spaceMemberRepo.removeSpaceMemberById(memberId, spaceId);
  return c.json({ success: true });
});

// POST /api/spaces/members/update-role
spaces.post('/members/update-role', zValidator('json', z.object({
  memberId: z.string(),
  spaceId: z.string(),
  role: z.enum(['reader', 'writer', 'admin']),
})), async (c) => {
  const user = c.get('user');
  const { memberId, spaceId, role } = c.req.valid('json');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, spaceId);
  if (!canManageMembers(highestSpaceRole(roles))) forbidden();

  const updated = await spaceMemberRepo.updateSpaceMember({ role }, memberId, spaceId);
  if (!updated) notFound('Member not found');
  return c.json(updated);
});

export default spaces;
```

**Step 2: Mount in `app.ts`**

```typescript
import spaceRoutes from './routes/spaces.routes';
app.route('/api/spaces', spaceRoutes);
```

**Step 3: Commit**

```bash
cd server && git add src/routes/spaces.routes.ts src/app.ts
git commit -m "feat: add space routes (CRUD, members)"
```

---

### Task 8: Page routes

**Files:**
- Create: `server/src/services/page.service.ts`
- Create: `server/src/routes/pages.routes.ts`
- Modify: `server/src/startup.ts`
- Modify: `server/src/app.ts`

**Step 1: Create `src/services/page.service.ts`**

```typescript
// server/src/services/page.service.ts
import type { PageRepo, PageHistoryRepo, BacklinkRepo } from '../database/repos';

export class PageService {
  constructor(
    private pageRepo: PageRepo,
    private pageHistoryRepo: PageHistoryRepo,
    private backlinkRepo: BacklinkRepo,
  ) {}

  async create(data: {
    title?: string;
    spaceId: string;
    workspaceId: string;
    creatorId: string;
    parentPageId?: string;
    icon?: string;
  }) {
    const slugId = Bun.randomUUIDv7().slice(0, 8);
    return this.pageRepo.insertPage({
      ...data,
      slugId,
      contributorIds: [data.creatorId],
      lastUpdatedById: data.creatorId,
    });
  }

  async update(pageId: string, updates: {
    title?: string;
    content?: unknown;
    textContent?: string;
    icon?: string;
    coverPhoto?: string;
    isLocked?: boolean;
  }, userId: string) {
    const page = await this.pageRepo.findById(pageId);
    if (!page) return null;

    // Add user to contributors if not already present
    const contributors = Array.isArray(page.contributorIds) ? page.contributorIds : [];
    if (!contributors.includes(userId)) contributors.push(userId);

    return this.pageRepo.updatePage({
      ...updates,
      contributorIds: contributors,
      lastUpdatedById: userId,
    }, pageId);
  }

  async softDelete(pageId: string, deletedById: string) {
    // Soft-delete page and all descendants
    const descendants = await this.pageRepo.getPageAndDescendants(pageId);
    const ids = descendants.map(p => p.id);
    await this.pageRepo.updatePages({ deletedAt: new Date().toISOString(), deletedById }, ids);
  }

  async forceDelete(pageId: string) {
    const descendants = await this.pageRepo.getPageAndDescendants(pageId);
    for (const p of descendants.reverse()) {
      await this.pageRepo.deletePage(p.id);
    }
  }

  async restore(pageId: string) {
    return this.pageRepo.restorePage(pageId);
  }

  async movePage(pageId: string, opts: { parentPageId?: string | null; position?: string }) {
    return this.pageRepo.updatePage(opts, pageId);
  }

  async getBreadcrumbs(pageId: string) {
    const crumbs: { id: string; title: string | null; icon: string | null }[] = [];
    let current = await this.pageRepo.findById(pageId);
    while (current) {
      crumbs.unshift({ id: current.id, title: current.title, icon: current.icon });
      if (!current.parentPageId) break;
      current = await this.pageRepo.findById(current.parentPageId);
    }
    return crumbs;
  }
}
```

**Step 2: Add `PageService` to `startup.ts`**

Add at the bottom of `startup.ts`:
```typescript
import { PageService } from './services/page.service';
export const pageService = new PageService(pageRepo, pageHistoryRepo, backlinkRepo);
```

**Step 3: Create `src/routes/pages.routes.ts`**

```typescript
// server/src/routes/pages.routes.ts
import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import type { AppVariables } from '../types';
import { pageRepo, pageHistoryRepo, spaceMemberRepo, pageService } from '../startup';
import { forbidden, notFound, badRequest } from '../lib/errors';
import { canReadSpace, canEditPage, canManagePage, canManageSpace, highestSpaceRole } from '../lib/permissions';

const pages = new Hono<{ Variables: AppVariables }>();

// POST /api/pages/info
pages.post('/info', zValidator('json', z.object({ pageId: z.string() })), async (c) => {
  const user = c.get('user');
  const { pageId } = c.req.valid('json');
  const page = await pageRepo.findById(pageId);
  if (!page) notFound('Page not found');
  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, page.spaceId);
  if (!canReadSpace(highestSpaceRole(roles))) forbidden();
  return c.json(page);
});

// POST /api/pages/create
pages.post('/create', zValidator('json', z.object({
  title: z.string().optional(),
  spaceId: z.string(),
  parentPageId: z.string().optional(),
  icon: z.string().optional(),
})), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  const dto = c.req.valid('json');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, dto.spaceId);
  if (!canEditPage(highestSpaceRole(roles))) forbidden();

  const page = await pageService.create({
    ...dto,
    workspaceId: workspace.id,
    creatorId: user.id,
  });
  return c.json(page);
});

// POST /api/pages/update
pages.post('/update', zValidator('json', z.object({
  pageId: z.string(),
  title: z.string().optional(),
  icon: z.string().optional(),
  coverPhoto: z.string().optional(),
  isLocked: z.boolean().optional(),
  content: z.unknown().optional(),
  textContent: z.string().optional(),
})), async (c) => {
  const user = c.get('user');
  const { pageId, ...updates } = c.req.valid('json');

  const page = await pageRepo.findById(pageId);
  if (!page) notFound('Page not found');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, page.spaceId);
  if (!canEditPage(highestSpaceRole(roles))) forbidden();

  const updated = await pageService.update(pageId, updates, user.id);
  return c.json(updated);
});

// POST /api/pages/delete
pages.post('/delete', zValidator('json', z.object({
  pageId: z.string(),
  permanentlyDelete: z.boolean().optional().default(false),
})), async (c) => {
  const user = c.get('user');
  const { pageId, permanentlyDelete } = c.req.valid('json');

  const page = await pageRepo.findById(pageId);
  if (!page) notFound('Page not found');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, page.spaceId);
  const role = highestSpaceRole(roles);

  if (permanentlyDelete) {
    if (!canManageSpace(role)) forbidden('Only space admins can permanently delete pages');
    await pageService.forceDelete(pageId);
  } else {
    if (!canManagePage(role)) forbidden();
    await pageService.softDelete(pageId, user.id);
  }

  return c.json({ success: true });
});

// POST /api/pages/restore
pages.post('/restore', zValidator('json', z.object({ pageId: z.string() })), async (c) => {
  const user = c.get('user');
  const { pageId } = c.req.valid('json');

  const page = await pageRepo.findById(pageId);
  if (!page) notFound('Page not found');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, page.spaceId);
  if (!canManagePage(highestSpaceRole(roles))) forbidden();

  await pageService.restore(pageId);
  return c.json({ success: true });
});

// POST /api/pages/recent
pages.post('/recent', zValidator('json', z.object({
  spaceId: z.string().optional(),
  limit: z.number().optional(),
  offset: z.number().optional(),
})), async (c) => {
  const user = c.get('user');
  const { spaceId, ...pagination } = c.req.valid('json');

  if (spaceId) {
    const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, spaceId);
    if (!canReadSpace(highestSpaceRole(roles))) forbidden();
    return c.json(await pageRepo.getRecentPagesInSpace(spaceId, pagination));
  }

  // Recent pages across all user's spaces (not yet implemented in repo — return empty)
  return c.json({ items: [], total: 0 });
});

// POST /api/pages/trash
pages.post('/trash', zValidator('json', z.object({
  spaceId: z.string(),
  limit: z.number().optional(),
  offset: z.number().optional(),
})), async (c) => {
  const user = c.get('user');
  const { spaceId, ...pagination } = c.req.valid('json');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, spaceId);
  if (!canManagePage(highestSpaceRole(roles))) forbidden();

  return c.json(await pageRepo.getDeletedPagesInSpace(spaceId, pagination));
});

// POST /api/pages/sidebar-pages
pages.post('/sidebar-pages', zValidator('json', z.object({
  spaceId: z.string().optional(),
  pageId: z.string().optional(),
})), async (c) => {
  const user = c.get('user');
  const { spaceId, pageId } = c.req.valid('json');

  if (!spaceId && !pageId) badRequest('Either spaceId or pageId must be provided');

  let resolvedSpaceId = spaceId;
  if (pageId) {
    const page = await pageRepo.findById(pageId);
    if (!page) forbidden();
    resolvedSpaceId = page.spaceId;
  }

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, resolvedSpaceId!);
  if (!canReadSpace(highestSpaceRole(roles))) forbidden();

  if (pageId) {
    return c.json(await pageRepo.getChildPages(pageId));
  }
  return c.json(await pageRepo.getRootPagesInSpace(resolvedSpaceId!));
});

// POST /api/pages/move
pages.post('/move', zValidator('json', z.object({
  pageId: z.string(),
  parentPageId: z.string().nullable().optional(),
  position: z.string().optional(),
})), async (c) => {
  const user = c.get('user');
  const { pageId, parentPageId, position } = c.req.valid('json');

  const page = await pageRepo.findById(pageId);
  if (!page) notFound('Page not found');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, page.spaceId);
  if (!canEditPage(highestSpaceRole(roles))) forbidden();

  const updated = await pageService.movePage(pageId, { parentPageId, position });
  return c.json(updated);
});

// POST /api/pages/breadcrumbs
pages.post('/breadcrumbs', zValidator('json', z.object({ pageId: z.string() })), async (c) => {
  const user = c.get('user');
  const { pageId } = c.req.valid('json');

  const page = await pageRepo.findById(pageId);
  if (!page) notFound('Page not found');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, page.spaceId);
  if (!canReadSpace(highestSpaceRole(roles))) forbidden();

  return c.json(await pageService.getBreadcrumbs(pageId));
});

// POST /api/pages/history
pages.post('/history', zValidator('json', z.object({
  pageId: z.string(),
  limit: z.number().optional(),
  offset: z.number().optional(),
})), async (c) => {
  const user = c.get('user');
  const { pageId, ...pagination } = c.req.valid('json');

  const page = await pageRepo.findById(pageId);
  if (!page) notFound('Page not found');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, page.spaceId);
  if (!canReadSpace(highestSpaceRole(roles))) forbidden();

  return c.json(await pageHistoryRepo.findPageHistoryByPageId(pageId, pagination));
});

// POST /api/pages/history/info
pages.post('/history/info', zValidator('json', z.object({ historyId: z.string() })), async (c) => {
  const user = c.get('user');
  const { historyId } = c.req.valid('json');

  const history = await pageHistoryRepo.findById(historyId);
  if (!history) notFound('History not found');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, history.spaceId);
  if (!canReadSpace(highestSpaceRole(roles))) forbidden();

  return c.json(history);
});

export default pages;
```

**Step 4: Mount in `app.ts`**

```typescript
import pageRoutes from './routes/pages.routes';
app.route('/api/pages', pageRoutes);
```

**Step 5: Commit**

```bash
cd server && git add src/services/page.service.ts src/routes/pages.routes.ts src/startup.ts src/app.ts
git commit -m "feat: add page service and page routes"
```

---

### Task 9: Group routes

**Files:**
- Create: `server/src/routes/groups.routes.ts`
- Modify: `server/src/app.ts`

**Step 1: Create `src/routes/groups.routes.ts`**

```typescript
// server/src/routes/groups.routes.ts
import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import type { AppVariables } from '../types';
import { groupRepo, groupUserRepo } from '../startup';
import { forbidden, notFound } from '../lib/errors';
import { canManageWorkspace } from '../lib/permissions';

const groups = new Hono<{ Variables: AppVariables }>();

// POST /api/groups/
groups.post('/', zValidator('json', z.object({
  limit: z.number().optional(),
  offset: z.number().optional(),
}).optional().default({})), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  const pagination = c.req.valid('json');
  const result = await groupRepo.getGroupsPaginated(workspace.id, pagination);
  return c.json(result);
});

// POST /api/groups/info
groups.post('/info', zValidator('json', z.object({ groupId: z.string() })), async (c) => {
  const { groupId } = c.req.valid('json');
  const workspace = c.get('workspace');
  const group = await groupRepo.findById(groupId, workspace.id);
  if (!group) notFound('Group not found');
  return c.json(group);
});

// POST /api/groups/create
groups.post('/create', zValidator('json', z.object({
  name: z.string().min(1),
  description: z.string().optional(),
})), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  if (!canManageWorkspace(user.role ?? '')) forbidden();

  const { name, description } = c.req.valid('json');
  const group = await groupRepo.insertGroup({ name, description, workspaceId: workspace.id });
  return c.json(group);
});

// POST /api/groups/update
groups.post('/update', zValidator('json', z.object({
  groupId: z.string(),
  name: z.string().min(1).optional(),
  description: z.string().optional(),
})), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  if (!canManageWorkspace(user.role ?? '')) forbidden();

  const { groupId, ...updates } = c.req.valid('json');
  const updated = await groupRepo.updateGroup(updates, groupId, workspace.id);
  if (!updated) notFound('Group not found');
  return c.json(updated);
});

// POST /api/groups/delete
groups.post('/delete', zValidator('json', z.object({ groupId: z.string() })), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  if (!canManageWorkspace(user.role ?? '')) forbidden();

  const { groupId } = c.req.valid('json');
  await groupRepo.deleteGroup(groupId, workspace.id);
  return c.json({ success: true });
});

// POST /api/groups/members
groups.post('/members', zValidator('json', z.object({
  groupId: z.string(),
  limit: z.number().optional(),
  offset: z.number().optional(),
})), async (c) => {
  const { groupId, ...pagination } = c.req.valid('json');
  const result = await groupUserRepo.getGroupUsersPaginated(groupId, pagination);
  return c.json(result);
});

// POST /api/groups/members/add
groups.post('/members/add', zValidator('json', z.object({
  groupId: z.string(),
  userIds: z.array(z.string()),
})), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  if (!canManageWorkspace(user.role ?? '')) forbidden();

  const { groupId, userIds } = c.req.valid('json');
  await Promise.all(userIds.map(userId =>
    groupUserRepo.insertGroupUser({ groupId, userId, workspaceId: workspace.id })
  ));
  return c.json({ success: true });
});

// POST /api/groups/members/remove
groups.post('/members/remove', zValidator('json', z.object({
  groupId: z.string(),
  userId: z.string(),
})), async (c) => {
  const user = c.get('user');
  if (!canManageWorkspace(user.role ?? '')) forbidden();

  const { groupId, userId } = c.req.valid('json');
  await groupUserRepo.removeGroupUser(groupId, userId);
  return c.json({ success: true });
});

export default groups;
```

**Step 2: Mount in `app.ts`**

```typescript
import groupRoutes from './routes/groups.routes';
app.route('/api/groups', groupRoutes);
```

**Step 3: Commit**

```bash
cd server && git add src/routes/groups.routes.ts src/app.ts
git commit -m "feat: add group routes (CRUD, members)"
```

---

### Task 10: Comment routes

**Files:**
- Create: `server/src/routes/comments.routes.ts`
- Modify: `server/src/app.ts`

**Step 1: Create `src/routes/comments.routes.ts`**

```typescript
// server/src/routes/comments.routes.ts
import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import type { AppVariables } from '../types';
import { commentRepo, pageRepo, spaceMemberRepo } from '../startup';
import { forbidden, notFound } from '../lib/errors';
import { canReadSpace, canEditPage, highestSpaceRole } from '../lib/permissions';

const comments = new Hono<{ Variables: AppVariables }>();

// POST /api/comments/
comments.post('/', zValidator('json', z.object({
  pageId: z.string(),
  limit: z.number().optional(),
  offset: z.number().optional(),
})), async (c) => {
  const user = c.get('user');
  const { pageId, ...pagination } = c.req.valid('json');

  const page = await pageRepo.findById(pageId);
  if (!page) notFound('Page not found');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, page.spaceId);
  if (!canReadSpace(highestSpaceRole(roles))) forbidden();

  return c.json(await commentRepo.getCommentsByPageId(pageId, pagination));
});

// POST /api/comments/info
comments.post('/info', zValidator('json', z.object({ commentId: z.string() })), async (c) => {
  const user = c.get('user');
  const { commentId } = c.req.valid('json');

  const comment = await commentRepo.findById(commentId);
  if (!comment) notFound('Comment not found');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, comment.spaceId);
  if (!canReadSpace(highestSpaceRole(roles))) forbidden();

  return c.json(comment);
});

// POST /api/comments/create
comments.post('/create', zValidator('json', z.object({
  pageId: z.string(),
  content: z.unknown(),
  parentCommentId: z.string().optional(),
  selection: z.unknown().optional(),
})), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  const dto = c.req.valid('json');

  const page = await pageRepo.findById(dto.pageId);
  if (!page) notFound('Page not found');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, page.spaceId);
  if (!canEditPage(highestSpaceRole(roles))) forbidden();

  const comment = await commentRepo.insertComment({
    ...dto,
    creatorId: user.id,
    spaceId: page.spaceId,
    workspaceId: workspace.id,
  });
  return c.json(comment);
});

// POST /api/comments/update
comments.post('/update', zValidator('json', z.object({
  commentId: z.string(),
  content: z.unknown(),
})), async (c) => {
  const user = c.get('user');
  const { commentId, content } = c.req.valid('json');

  const comment = await commentRepo.findById(commentId);
  if (!comment) notFound('Comment not found');

  // Only comment author or space admin can edit
  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, comment.spaceId);
  const role = highestSpaceRole(roles);
  if (comment.creatorId !== user.id && !canEditPage(role)) forbidden();

  const updated = await commentRepo.updateComment({ content }, commentId);
  return c.json(updated);
});

// POST /api/comments/delete
comments.post('/delete', zValidator('json', z.object({ commentId: z.string() })), async (c) => {
  const user = c.get('user');
  const { commentId } = c.req.valid('json');

  const comment = await commentRepo.findById(commentId);
  if (!comment) notFound('Comment not found');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, comment.spaceId);
  const role = highestSpaceRole(roles);
  if (comment.creatorId !== user.id && !canEditPage(role)) forbidden();

  await commentRepo.deleteComment(commentId);
  return c.json({ success: true });
});

export default comments;
```

**Step 2: Mount in `app.ts`**

```typescript
import commentRoutes from './routes/comments.routes';
app.route('/api/comments', commentRoutes);
```

**Step 3: Commit**

```bash
cd server && git add src/routes/comments.routes.ts src/app.ts
git commit -m "feat: add comment routes"
```

---

### Task 11: Notification routes

**Files:**
- Create: `server/src/routes/notifications.routes.ts`
- Modify: `server/src/app.ts`

**Step 1: Create `src/routes/notifications.routes.ts`**

```typescript
// server/src/routes/notifications.routes.ts
import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import type { AppVariables } from '../types';
import { notificationRepo } from '../startup';

const notifications = new Hono<{ Variables: AppVariables }>();

// POST /api/notifications/
notifications.post('/', zValidator('json', z.object({
  limit: z.number().optional(),
  offset: z.number().optional(),
}).optional().default({})), async (c) => {
  const user = c.get('user');
  const pagination = c.req.valid('json');
  return c.json(await notificationRepo.getNotificationsByUserId(user.id, pagination));
});

// POST /api/notifications/unread-count
notifications.post('/unread-count', async (c) => {
  const user = c.get('user');
  const count = await notificationRepo.getUnreadCount(user.id);
  return c.json({ count });
});

// POST /api/notifications/mark-read
notifications.post('/mark-read', zValidator('json', z.object({
  notificationIds: z.array(z.string()).optional(),
})), async (c) => {
  const user = c.get('user');
  const { notificationIds = [] } = c.req.valid('json');
  if (notificationIds.length > 0) {
    await notificationRepo.markMultipleAsRead(notificationIds, user.id);
  }
  return c.json({ success: true });
});

// POST /api/notifications/mark-all-read
notifications.post('/mark-all-read', async (c) => {
  const user = c.get('user');
  await notificationRepo.markAllAsRead(user.id);
  return c.json({ success: true });
});

export default notifications;
```

**Step 2: Mount in `app.ts`**

```typescript
import notificationRoutes from './routes/notifications.routes';
app.route('/api/notifications', notificationRoutes);
```

**Step 3: Commit**

```bash
cd server && git add src/routes/notifications.routes.ts src/app.ts
git commit -m "feat: add notification routes"
```

---

### Task 12: Share routes

**Files:**
- Create: `server/src/routes/shares.routes.ts`
- Modify: `server/src/app.ts`

**Step 1: Create `src/routes/shares.routes.ts`**

```typescript
// server/src/routes/shares.routes.ts
import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import type { AppVariables } from '../types';
import { shareRepo, pageRepo, spaceMemberRepo } from '../startup';
import { forbidden, notFound } from '../lib/errors';
import { canReadSpace, canManageShares, highestSpaceRole } from '../lib/permissions';

const shares = new Hono<{ Variables: AppVariables }>();

// POST /api/shares/ — list shares for user's spaces
shares.post('/', zValidator('json', z.object({
  limit: z.number().optional(),
  offset: z.number().optional(),
}).optional().default({})), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  return c.json(await shareRepo.getSharesByWorkspace(workspace.id));
});

// POST /api/shares/info (public)
shares.post('/info', zValidator('json', z.object({ shareId: z.string() })), async (c) => {
  const { shareId } = c.req.valid('json');
  const share = await shareRepo.findById(shareId);
  if (!share) notFound('Share not found');
  return c.json(share);
});

// POST /api/shares/for-page
shares.post('/for-page', zValidator('json', z.object({ pageId: z.string() })), async (c) => {
  const user = c.get('user');
  const { pageId } = c.req.valid('json');

  const page = await pageRepo.findById(pageId);
  if (!page) notFound('Page not found');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, page.spaceId);
  if (!canReadSpace(highestSpaceRole(roles))) forbidden();

  const share = await shareRepo.findByPageId(pageId);
  return c.json(share ?? null);
});

// POST /api/shares/create
shares.post('/create', zValidator('json', z.object({
  pageId: z.string(),
  includeSubpages: z.boolean().optional().default(true),
})), async (c) => {
  const user = c.get('user');
  const workspace = c.get('workspace');
  const { pageId, includeSubpages } = c.req.valid('json');

  const page = await pageRepo.findById(pageId);
  if (!page) notFound('Page not found');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, page.spaceId);
  if (!canManageShares(highestSpaceRole(roles))) forbidden();

  const existing = await shareRepo.findByPageId(pageId);
  if (existing) return c.json(existing);

  const share = await shareRepo.insertShare({
    pageId,
    includeSubpages,
    spaceId: page.spaceId,
    workspaceId: workspace.id,
    creatorId: user.id,
  });
  return c.json(share);
});

// POST /api/shares/update
shares.post('/update', zValidator('json', z.object({
  shareId: z.string(),
  includeSubpages: z.boolean().optional(),
  searchIndexing: z.boolean().optional(),
})), async (c) => {
  const user = c.get('user');
  const { shareId, ...updates } = c.req.valid('json');

  const share = await shareRepo.findById(shareId);
  if (!share) notFound('Share not found');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, share.spaceId);
  if (!canManageShares(highestSpaceRole(roles))) forbidden();

  const updated = await shareRepo.updateShare(updates, shareId);
  return c.json(updated);
});

// POST /api/shares/delete
shares.post('/delete', zValidator('json', z.object({ shareId: z.string() })), async (c) => {
  const user = c.get('user');
  const { shareId } = c.req.valid('json');

  const share = await shareRepo.findById(shareId);
  if (!share) notFound('Share not found');

  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, share.spaceId);
  if (!canManageShares(highestSpaceRole(roles))) forbidden();

  await shareRepo.deleteShare(shareId);
  return c.json({ success: true });
});

export default shares;
```

**Step 2: Mount in `app.ts`**

```typescript
import shareRoutes from './routes/shares.routes';
app.route('/api/shares', shareRoutes);
```

**Step 3: Commit**

```bash
cd server && git add src/routes/shares.routes.ts src/app.ts
git commit -m "feat: add share routes"
```

---

### Task 13: Search routes (stub) + Attachment routes (stub)

**Files:**
- Create: `server/src/routes/search.routes.ts`
- Create: `server/src/routes/attachments.routes.ts`
- Modify: `server/src/app.ts`

**Step 1: Create `src/routes/search.routes.ts`** — stub until Phase 6 (FTS5)

```typescript
// server/src/routes/search.routes.ts
import { Hono } from 'hono';
import type { AppVariables } from '../types';

const search = new Hono<{ Variables: AppVariables }>();

// POST /api/search — stub until Phase 6 (FTS5)
search.post('/', async (c) => c.json({ items: [], total: 0 }));
search.post('/suggest', async (c) => c.json({ items: [] }));
search.post('/share-search', async (c) => c.json({ items: [], total: 0 }));

export default search;
```

**Step 2: Create `src/routes/attachments.routes.ts`** — file upload/serve stub

```typescript
// server/src/routes/attachments.routes.ts
import { Hono } from 'hono';
import type { AppVariables } from '../types';
import { attachmentRepo, spaceMemberRepo } from '../startup';
import { forbidden, notFound } from '../lib/errors';
import { canReadSpace, highestSpaceRole } from '../lib/permissions';

const attachments = new Hono<{ Variables: AppVariables }>();

// POST /api/files/upload — TODO: implement full file upload (Phase 5)
attachments.post('/upload', async (c) => {
  return c.json({ error: 'File upload not yet implemented' }, 501);
});

// GET /api/files/:fileId/:fileName
attachments.get('/:fileId/:fileName', async (c) => {
  const user = c.get('user');
  const { fileId } = c.req.param();

  const attachment = await attachmentRepo.findById(fileId);
  if (!attachment) notFound('File not found');

  if (attachment.spaceId) {
    const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, attachment.spaceId);
    if (!canReadSpace(highestSpaceRole(roles))) forbidden();
  }

  // TODO(Phase 5): stream file from storage
  return c.json({ error: 'File serving not yet implemented' }, 501);
});

export default attachments;
```

**Step 3: Mount both in `app.ts`**

```typescript
import searchRoutes from './routes/search.routes';
import attachmentRoutes from './routes/attachments.routes';
app.route('/api/search', searchRoutes);
app.route('/api/files', attachmentRoutes);
```

**Step 4: Commit**

```bash
cd server && git add src/routes/search.routes.ts src/routes/attachments.routes.ts src/app.ts
git commit -m "feat: add search stub and attachment stub routes"
```

---

### Task 14: End-to-end smoke test + final verification

**Step 1: Verify the server starts cleanly**

```bash
cd server && bun run src/index.ts &
sleep 1
curl -s http://localhost:3000/healthz | jq .
```

Expected: `{"status":"ok"}`

**Step 2: Verify all routes are mounted**

```bash
curl -s -X POST http://localhost:3000/api/workspace/public \
  -H "Host: localhost" \
  -H "Content-Type: application/json" \
  -d '{}' | jq .name
```

Expected: workspace name string.

**Step 3: Verify auth middleware rejects missing auth**

```bash
curl -s -X POST http://localhost:3000/api/users/me \
  -H "Host: localhost" \
  -H "Content-Type: application/json" | jq .error
```

Expected: `"Unauthorized"`

**Step 4: Verify TypeScript has no new errors**

```bash
kill %1
cd server && bunx tsc --noEmit 2>&1
```

Expected: no errors (or only pre-existing errors from schema/repo files).

**Step 5: Final commit**

```bash
cd server && git add -A
git commit -m "chore: phase 2 complete — Hono HTTP server with all API routes"
```

---

## Missing repo methods to add during implementation

Some routes call repo methods that need to be added during Task execution. Add them as you encounter `method does not exist` TypeScript errors:

| Method | Repo | Description |
|---|---|---|
| `groupRepo.getGroupsPaginated(workspaceId, opts)` | `GroupRepo` | Paginated group list |
| `groupRepo.findById(groupId, workspaceId)` | `GroupRepo` | Find by ID |
| `groupRepo.insertGroup(data)` | `GroupRepo` | Create group |
| `groupRepo.updateGroup(updates, groupId, workspaceId)` | `GroupRepo` | Update group |
| `groupRepo.deleteGroup(groupId, workspaceId)` | `GroupRepo` | Delete group |
| `groupUserRepo.getGroupUsersPaginated(groupId, opts)` | `GroupUserRepo` | Paginated members |
| `groupUserRepo.insertGroupUser(data)` | `GroupUserRepo` | Add member |
| `groupUserRepo.removeGroupUser(groupId, userId)` | `GroupUserRepo` | Remove member |
| `commentRepo.getCommentsByPageId(pageId, opts)` | `CommentRepo` | List comments |
| `commentRepo.findById(commentId)` | `CommentRepo` | Find comment |
| `commentRepo.insertComment(data)` | `CommentRepo` | Create comment |
| `commentRepo.updateComment(updates, commentId)` | `CommentRepo` | Update comment |
| `commentRepo.deleteComment(commentId)` | `CommentRepo` | Delete comment |
| `notificationRepo.getNotificationsByUserId(userId, opts)` | `NotificationRepo` | List notifications |
| `notificationRepo.getUnreadCount(userId)` | `NotificationRepo` | Unread count |
| `notificationRepo.markMultipleAsRead(ids, userId)` | `NotificationRepo` | Mark as read |
| `notificationRepo.markAllAsRead(userId)` | `NotificationRepo` | Mark all read |
| `shareRepo.getSharesByWorkspace(workspaceId)` | `ShareRepo` | List shares |
| `shareRepo.findById(shareId)` | `ShareRepo` | Find share |
| `shareRepo.findByPageId(pageId)` | `ShareRepo` | Find share for page |
| `shareRepo.insertShare(data)` | `ShareRepo` | Create share |
| `shareRepo.updateShare(updates, shareId)` | `ShareRepo` | Update share |
| `shareRepo.deleteShare(shareId)` | `ShareRepo` | Delete share |
| `attachmentRepo.findById(fileId)` | `AttachmentRepo` | Find attachment |

When a method is missing: add it to the appropriate file in `server/src/database/repos/`, following the patterns already established in existing repo files (use drizzle-orm queries, `.returning()`, etc.).
