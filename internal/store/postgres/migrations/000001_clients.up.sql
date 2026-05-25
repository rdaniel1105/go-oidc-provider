-- 000001_clients.up.sql
-- OAuth/OIDC client registry.
--
-- Notes on a few columns:
--   client_secret_hash              bcrypt hash. NULL for public clients
--                                   (e.g. SPAs using PKCE with auth_method
--                                   = "none").
--   redirect_uris / grant_types /
--   response_types / scopes         Stored as TEXT[] for atomic update in
--                                   the YAML-reconcile flow. Lookups never
--                                   filter by individual array elements, so
--                                   no GIN indexes are needed.
--   client_notification_endpoint /
--   backchannel_token_delivery_mode CIBA-only fields. NULL for clients that
--                                   only use the auth-code flow.
--   deleted_at                      Soft-delete. The YAML reconciler marks
--                                   removed clients as deleted instead of
--                                   hard-dropping rows so audit trails
--                                   referencing client_id survive.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE clients (
    id                              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id                       TEXT NOT NULL,
    client_secret_hash              TEXT,
    redirect_uris                   TEXT[] NOT NULL DEFAULT '{}',
    grant_types                     TEXT[] NOT NULL DEFAULT '{}',
    response_types                  TEXT[] NOT NULL DEFAULT '{}',
    scopes                          TEXT[] NOT NULL DEFAULT '{}',
    token_endpoint_auth_method      TEXT NOT NULL,
    client_notification_endpoint    TEXT,
    backchannel_token_delivery_mode TEXT,
    created_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at                      TIMESTAMPTZ
);

-- client_id must be globally unique among live (non-deleted) rows. Allowing
-- duplicates among soft-deleted rows lets the same client_id be revived
-- later without colliding with audit history.
CREATE UNIQUE INDEX clients_client_id_unique_live
    ON clients (client_id)
    WHERE deleted_at IS NULL;
