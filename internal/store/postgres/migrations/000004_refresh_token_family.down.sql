DROP INDEX IF EXISTS refresh_tokens_family_live;
ALTER TABLE refresh_tokens
    DROP COLUMN IF EXISTS family_id,
    DROP COLUMN IF EXISTS auth_time;
