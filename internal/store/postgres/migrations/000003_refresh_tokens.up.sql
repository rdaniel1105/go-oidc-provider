-- 000003_refresh_tokens.up.sql
-- Refresh-token registry.
--
-- The raw token never lives at rest — only the SHA-256 hash. This mirrors
-- the same-pattern used for session tokens in the passkey service and lets
-- the database leak harmlessly: an attacker reading the table sees
-- post-image hashes, not bearer credentials.
--
-- revoked_at, not deleted_at: refresh tokens are revoked (a meaningful
-- lifecycle event the rotation logic depends on observing), not deleted.
-- A revoked row that is later presented is the theft signal that triggers
-- family-wide revocation.
--
-- Notes on a few columns:
--   token_hash  Lowercase hex of SHA-256 over the URL-safe token string.
--               Unique across the whole table (revoked rows included) so
--               replays of an already-revoked token are detectable by a
--               simple lookup.
--   client_id   TEXT, not a FK to clients.id, because clients are keyed
--               by client_id externally and the YAML reconciler may rotate
--               the row's UUID under us.
--   op_user_id  FK to op_users.id with ON DELETE RESTRICT (the default).
--               A live refresh token outlives the user only if the user
--               row is soft-deleted, which keeps the FK valid.

CREATE TABLE refresh_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    op_user_id UUID NOT NULL REFERENCES op_users(id),
    scope      TEXT[] NOT NULL DEFAULT '{}',
    issued_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX refresh_tokens_token_hash_unique
    ON refresh_tokens (token_hash);

CREATE INDEX refresh_tokens_op_user_live
    ON refresh_tokens (op_user_id)
    WHERE revoked_at IS NULL;
