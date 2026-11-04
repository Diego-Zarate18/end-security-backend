-- Alinea el esquema con el diagrama end_security_db (versión 2026-11-04).
-- Supone tablas vacías en desarrollo (las columnas cambiadas no tienen conversión con datos reales).

-- users: auth_hash pasa a TEXT (hash Argon2id en formato PHC), nueva columna kdf_memory_kib
ALTER TABLE "users"
  ALTER COLUMN "auth_hash" SET DATA TYPE TEXT USING convert_from("auth_hash", 'UTF8'),
  ADD COLUMN "kdf_memory_kib" INTEGER NOT NULL DEFAULT 65536,
  ALTER COLUMN "key_version" SET DEFAULT 1,
  ALTER COLUMN "vault_revision" SET DEFAULT 0,
  ALTER COLUMN "purged_through_revision" SET DEFAULT 0;
ALTER TABLE "users" ALTER COLUMN "kdf_memory_kib" DROP DEFAULT;

-- email_verifications: intentos inician en 0
ALTER TABLE "email_verifications" ALTER COLUMN "attempts" SET DEFAULT 0;

-- audit_log_pii: ip pasa de INTEGER a INET (no hay conversión posible)
ALTER TABLE "audit_log_pii" DROP COLUMN "ip",
  ADD COLUMN "ip" INET NOT NULL;

-- sessions: búsqueda y unicidad del hash del refresh token
CREATE UNIQUE INDEX "sessions_refresh_token_hash_key" ON "sessions"("refresh_token_hash");

-- Restricciones del diagrama que Prisma no modela (defensa en profundidad)
ALTER TABLE "email_verifications"
  ADD CONSTRAINT "email_verifications_purpose_check" CHECK ("purpose" IN ('verify_email', 'change_email')),
  ADD CONSTRAINT "email_verifications_attempts_check" CHECK ("attempts" BETWEEN 0 AND 5);
ALTER TABLE "audit_log"
  ADD CONSTRAINT "audit_log_outcome_check" CHECK ("outcome" IN ('success', 'failure'));
ALTER TABLE "two_factor"
  ADD CONSTRAINT "two_factor_status_check" CHECK ("status" IN ('pending', 'active'));
ALTER TABLE "users"
  ADD CONSTRAINT "users_kdf_params_check" CHECK ("kdf_memory_kib" >= 19456 AND "kdf_iterations" >= 2 AND "kdf_parallelism" >= 1);
