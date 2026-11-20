# NETSCOPE X Security Specification & Invariants

## 1. Data Invariants
1. **Identity Isolation**: Every user profile (`/users/{userId}`), analyst settings (`/analystSettings/{userId}`), incident (`/incidents/{incidentId}`), and capture session (`/captureSessions/{sessionId}`) is strictly scoped to `request.auth.uid` with `request.auth.token.email_verified == true`.
2. **No Shadow Fields**: Every write must pass strict `keys().hasAll(...) && keys().hasOnly(...)` validation on create and `affectedKeys().hasOnly(...)` on update.
3. **Immutable Ownership & Creation Timestamps**: `ownerId`, `incidentId`/`sessionId`, and `createdAt` cannot be modified after creation.
4. **Server Temporal Integrity**: `createdAt` and `updatedAt` must equal `request.time`.
5. **Terminal State Locking**: Once an incident reaches `status == "resolved"` (unless reopened only? No — terminal state lock prevents arbitrary tampering once resolved).
6. **Bounded Resource Sizes**: Every string property enforces strict `.size()` bounds; IDs must match `^[a-zA-Z0-9_-]+$` and length `<= 128`.

## 2. Dirty Dozen Adversarial Payloads
1. Unauthenticated read on `/incidents/{id}` -> `PERMISSION_DENIED`.
2. Unverified email (`email_verified: false`) create on `/incidents/{id}` -> `PERMISSION_DENIED`.
3. Cross-tenant `get` on `/users/{otherUid}` (PII email isolation) -> `PERMISSION_DENIED`.
4. Blanket `list` on `/incidents` without `ownerId == request.auth.uid` filter -> `PERMISSION_DENIED`.
5. Identity spoofing (`ownerId: "victim-uid"`) on `/incidents/{id}` create -> `PERMISSION_DENIED`.
6. Ghost/shadow field (`isAdmin: true`) injected on `/users/{uid}` create -> `PERMISSION_DENIED`.
7. Client-forged timestamp (`createdAt: "2020-01-01T00:00:00Z"`) instead of `request.time` -> `PERMISSION_DENIED`.
8. Oversized ID poisoning (`1500`-char document ID) -> `PERMISSION_DENIED`.
9. Oversized `notes` (`> 4000` chars) on `/incidents/{id}` update -> `PERMISSION_DENIED`.
10. Invalid `severity` enum (`"SuperUltra"`) on `/incidents/{id}` -> `PERMISSION_DENIED`.
11. Mutating immutable `ownerId` or `createdAt` on `/incidents/{id}` update -> `PERMISSION_DENIED`.
12. Modifying an already `resolved` incident -> `PERMISSION_DENIED`.
