-- 000004_refresh_token_family.up.sql
-- Add the columns the rotation flow needs:
--   family_id   Groups every refresh token descended from one initial
--               authentication. On replay of an already-revoked token,
--               the whole family is revoked so the attacker's chain dies.
--   auth_time   The original `auth_time` claim from the authentication
--               that started this chain. Carried through rotations so
--               refreshed ID tokens still report the real moment the
--               user proved themselves, not the moment they last
--               refreshed.

ALTER TABLE refresh_tokens
    ADD COLUMN family_id UUID NOT NULL DEFAULT gen_random_uuid(),
    ADD COLUMN auth_time TIMESTAMPTZ NOT NULL DEFAULT now();

-- A live family is one whose tokens are not all revoked. The partial
-- index speeds up family-wide revocation when a stolen token is
-- detected.
CREATE INDEX refresh_tokens_family_live
    ON refresh_tokens (family_id)
    WHERE revoked_at IS NULL;
