# Phase 2: HTTP Server & Routing — Design

## Goal

Build the Hono HTTP server layer: entry point, middleware, singleton services, permission helpers, and all API route handlers that mirror the existing NestJS reference server.

## Architecture

Hono app mounted on `Bun.serve()`. All repos and services are module-level singletons constructed once in `startup.ts`. Routes import directly from `startup.ts` — no DI framework, no context injection. Auth middleware validates Better Auth sessions. Workspace middleware resolves workspace from `Host` header. Simple role-check helpers replace CASL.

## Tech Stack

Bun, Hono v4, `drizzle-orm/bun-sqlite`, Better Auth, Zod + `@hono/zod-validator`

---

## File Structure

```
server/src/
├── index.ts                      ← Bun.serve() entry point, runs migration on boot
├── app.ts                        ← Hono app, middleware chain, route mounting
├── startup.ts                    ← singleton repos + services (constructed once)
├── middleware/
│   ├── auth.middleware.ts        ← Better Auth session → c.set('user'), 401 if missing
│   ├── workspace.middleware.ts   ← Host header → c.set('workspace'), 404 if missing
│   └── error.middleware.ts       ← global try/catch → typed errors or 500
├── routes/
│   ├── auth.routes.ts            ← proxy to Better Auth + /collab-token
│   ├── pages.routes.ts
│   ├── spaces.routes.ts
│   ├── users.routes.ts
│   ├── groups.routes.ts
│   ├── comments.routes.ts
│   ├── attachments.routes.ts
│   ├── search.routes.ts          ← stub (FTS5 is Phase 6)
│   ├── shares.routes.ts
│   ├── workspaces.routes.ts
│   └── notifications.routes.ts
├── services/
│   ├── page.service.ts           ← create, update, move, duplicate, delete, breadcrumbs
│   ├── space.service.ts          ← create, member management
│   ├── workspace.service.ts      ← setup, invitations, settings
│   ├── comment.service.ts        ← threaded comments
│   ├── attachment.service.ts     ← Bun.write + metadata
│   ├── share.service.ts          ← public share create/revoke
│   └── notification.service.ts  ← generate + mark read
└── lib/
    ├── permissions.ts            ← role-check helper functions
    ├── errors.ts                 ← HttpError class + typed throw helpers
    └── unaccent.ts               ← (already exists)
```

---

## Section 1: Entry Point

**`src/index.ts`**
- Runs `migrate(db, { migrationsFolder })` on startup
- Starts `Bun.serve({ fetch: app.fetch, port })`
- WebSocket upgrade paths (`/collab`) handled before Hono in `upgrade` hook (stubbed for Phase 4)

**`src/app.ts`**
- Creates `new Hono()`
- Mounts `errorMiddleware` (outermost)
- Mounts `workspaceMiddleware` on all `/api/*`
- Mounts `authMiddleware` on all `/api/*` except `/api/auth/*`
- Mounts all route files under `/api/`

---

## Section 2: Startup Singletons

**`src/startup.ts`** — constructed once at module load, never re-instantiated:

```typescript
// Repos
export const workspaceRepo = new WorkspaceRepo(db);
export const userRepo      = new UserRepo(db);
export const pageRepo      = new PageRepo(db);
export const pageHistoryRepo = new PageHistoryRepo(db);
export const backlinkRepo  = new BacklinkRepo(db);
export const spaceRepo     = new SpaceRepo(db);
export const spaceMemberRepo = new SpaceMemberRepo(db);
export const groupRepo     = new GroupRepo(db);
export const groupUserRepo = new GroupUserRepo(db);
export const commentRepo   = new CommentRepo(db);
export const attachmentRepo = new AttachmentRepo(db);
export const shareRepo     = new ShareRepo(db);
export const notificationRepo = new NotificationRepo(db);
export const watcherRepo   = new WatcherRepo(db);

// Services
export const pageService         = new PageService(pageRepo, backlinkRepo, pageHistoryRepo);
export const spaceService        = new SpaceService(spaceRepo, spaceMemberRepo);
export const workspaceService    = new WorkspaceService(workspaceRepo, userRepo);
export const commentService      = new CommentService(commentRepo, pageRepo);
export const attachmentService   = new AttachmentService(attachmentRepo);
export const shareService        = new ShareService(shareRepo, pageRepo, spaceRepo);
export const notificationService = new NotificationService(notificationRepo, watcherRepo);
```

---

## Section 3: Middleware

### `auth.middleware.ts`
```typescript
export const authMiddleware = createMiddleware(async (c, next) => {
  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session) return c.json({ error: 'Unauthorized' }, 401);
  c.set('user', session.user);
  c.set('session', session.session);
  await next();
});
```

### `workspace.middleware.ts`
```typescript
export const workspaceMiddleware = createMiddleware(async (c, next) => {
  const host = c.req.header('host') ?? '';
  const hostname = host.split(':')[0];
  let workspace = await workspaceRepo.findByHostname(hostname);
  if (!workspace) workspace = await workspaceRepo.findFirst(); // dev fallback
  if (!workspace) return c.json({ error: 'Workspace not found' }, 404);
  c.set('workspace', workspace);
  await next();
});
```

### `error.middleware.ts`
```typescript
export const errorMiddleware = createMiddleware(async (c, next) => {
  try {
    await next();
  } catch (err) {
    if (err instanceof HttpError) return c.json({ error: err.message }, err.status);
    console.error(err);
    return c.json({ error: 'Internal server error' }, 500);
  }
});
```

---

## Section 4: Permissions

**`src/lib/permissions.ts`** — no external library:

```typescript
// Space roles: reader < writer < admin
export const canReadSpace    = (role: string) => ['reader','writer','admin'].includes(role);
export const canEditPage     = (role: string) => ['writer','admin'].includes(role);
export const canManagePage   = (role: string) => ['writer','admin'].includes(role);
export const canManageSpace  = (role: string) => role === 'admin';
export const canManageMembers = (role: string) => role === 'admin';

// Workspace roles: member < admin < owner
export const canManageWorkspace = (role: string) => ['owner','admin'].includes(role);
export const isWorkspaceOwner   = (role: string) => role === 'owner';
```

**Usage pattern in routes:**
```typescript
const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, spaceId);
const role  = highestRole(roles); // picks admin > writer > reader
if (!canEditPage(role)) throw new HttpError(403, 'Forbidden');
```

**`src/lib/errors.ts`**
```typescript
export class HttpError extends Error {
  constructor(public status: number, message: string) { super(message); }
}
export const notFound    = (msg = 'Not found')    => { throw new HttpError(404, msg); };
export const forbidden   = (msg = 'Forbidden')    => { throw new HttpError(403, msg); };
export const badRequest  = (msg = 'Bad request')  => { throw new HttpError(400, msg); };
```

---

## Section 5: Routes Shape

All routes follow this pattern — thin handlers, Zod validation, service/repo call, JSON return:

```typescript
// POST /api/pages/info
pages.post('/info', zValidator('json', pageInfoSchema), async (c) => {
  const { pageId } = c.req.valid('json');
  const user = c.get('user');
  const page = await pageRepo.findById(pageId);
  if (!page) notFound('Page not found');
  const roles = await spaceMemberRepo.getUserSpaceRoles(user.id, page.spaceId);
  if (!canReadSpace(highestRole(roles))) forbidden();
  return c.json(page);
});
```

Auth routes proxy directly to Better Auth:
```typescript
auth.all('/*', (c) => betterAuth.handler(c.req.raw));
```
Plus one custom endpoint: `POST /api/auth/collab-token` — issues a short-lived JWT for the collab WebSocket (Phase 4).

---

## Section 6: Out of Scope for Phase 2

| Feature | Phase |
|---|---|
| WebSocket / Yjs collab | 4 |
| FTS5 search (search routes return `[]` stub) | 6 |
| File import / export (stub routes only) | 5 |
| Static file serving + SPA fallback | last step |
| Email sending | 3 |

---

## Hono Context Type Augmentation

To get full TypeScript inference on `c.get('user')` etc., declare the variable map:

```typescript
// src/types.ts
import type { User, Session } from 'better-auth';
import type { workspaces } from './database/schema';

type Workspace = typeof workspaces.$inferSelect;

export type AppVariables = {
  user: User;
  session: Session;
  workspace: Workspace;
};

// In app.ts:
const app = new Hono<{ Variables: AppVariables }>();
```
