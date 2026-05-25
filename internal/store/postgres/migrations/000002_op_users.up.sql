-- 000002_op_users.up.sql
-- The OP's authoritative user record.
--
-- op_users is intentionally separate from the user table inside the passkey
-- service: this row owns the OIDC-relevant fields (email, phone, display
-- name) while the passkey service owns the credential bindings. The two are
-- joined by passkey_user_id, which is an opaque foreign reference into the
-- passkey service's user table.
--
-- Notes on a few columns:
--   email           Used as the CIBA login_hint and as the `email` claim.
--                   Unique among live rows.
--   phone_e164      WhatsApp / SMS delivery target. Optional — clients
--                   that don't use phone-channel notifiers can leave it
--                   empty. Unique among live rows when present.
--   passkey_user_id Foreign reference to go-passkey-auth's users.id. Not a
--                   FOREIGN KEY because the passkey service runs in its
--                   own database; integrity is maintained at the
--                   application layer.

CREATE TABLE op_users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    phone_e164      TEXT,
    passkey_user_id UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ
);

CREATE UNIQUE INDEX op_users_email_unique_live
    ON op_users (email)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX op_users_phone_e164_unique_live
    ON op_users (phone_e164)
    WHERE deleted_at IS NULL AND phone_e164 IS NOT NULL;

CREATE UNIQUE INDEX op_users_passkey_user_id_unique_live
    ON op_users (passkey_user_id)
    WHERE deleted_at IS NULL;
