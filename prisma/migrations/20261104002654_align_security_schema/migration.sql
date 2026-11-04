/*
  Warnings:

  - The primary key for the `users` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - You are about to drop the column `createdAt` on the `users` table. All the data in the column will be lost.
  - You are about to drop the column `isTwoFactorEnabled` on the `users` table. All the data in the column will be lost.
  - You are about to drop the column `passwordHash` on the `users` table. All the data in the column will be lost.
  - You are about to drop the column `twoFactorSecret` on the `users` table. All the data in the column will be lost.
  - You are about to drop the column `updatedAt` on the `users` table. All the data in the column will be lost.
  - You are about to drop the `audit_logs` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `vaults` table. If the table is not empty, all the data it contains will be lost.
  - Added the required column `auth_hash` to the `users` table without a default value. This is not possible if the table is not empty.
  - Added the required column `display_name` to the `users` table without a default value. This is not possible if the table is not empty.
  - Added the required column `kdf_iterations` to the `users` table without a default value. This is not possible if the table is not empty.
  - Added the required column `kdf_parallelism` to the `users` table without a default value. This is not possible if the table is not empty.
  - Added the required column `kdf_salt` to the `users` table without a default value. This is not possible if the table is not empty.
  - Added the required column `key_version` to the `users` table without a default value. This is not possible if the table is not empty.
  - Added the required column `purged_through_revision` to the `users` table without a default value. This is not possible if the table is not empty.
  - Added the required column `pvk_ciphertext` to the `users` table without a default value. This is not possible if the table is not empty.
  - Added the required column `pvk_nonce` to the `users` table without a default value. This is not possible if the table is not empty.
  - Added the required column `updated_at` to the `users` table without a default value. This is not possible if the table is not empty.
  - Added the required column `vault_revision` to the `users` table without a default value. This is not possible if the table is not empty.
  - Changed the type of `id` on the `users` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.

*/
-- DropForeignKey
ALTER TABLE "audit_logs" DROP CONSTRAINT "audit_logs_userId_fkey";

-- DropForeignKey
ALTER TABLE "vaults" DROP CONSTRAINT "vaults_userId_fkey";

-- AlterTable
ALTER TABLE "users" DROP CONSTRAINT "users_pkey",
DROP COLUMN "createdAt",
DROP COLUMN "isTwoFactorEnabled",
DROP COLUMN "passwordHash",
DROP COLUMN "twoFactorSecret",
DROP COLUMN "updatedAt",
ADD COLUMN     "anonymized_at" TIMESTAMPTZ(6),
ADD COLUMN     "auth_hash" BYTEA NOT NULL,
ADD COLUMN     "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN     "deleted_at" TIMESTAMPTZ(6),
ADD COLUMN     "display_name" TEXT NOT NULL,
ADD COLUMN     "email_verified_at" TIMESTAMPTZ(6),
ADD COLUMN     "kdf_iterations" INTEGER NOT NULL,
ADD COLUMN     "kdf_parallelism" SMALLINT NOT NULL,
ADD COLUMN     "kdf_salt" BYTEA NOT NULL,
ADD COLUMN     "key_version" INTEGER NOT NULL,
ADD COLUMN     "purged_through_revision" BIGINT NOT NULL,
ADD COLUMN     "pvk_ciphertext" BYTEA NOT NULL,
ADD COLUMN     "pvk_nonce" BYTEA NOT NULL,
ADD COLUMN     "updated_at" TIMESTAMPTZ(6) NOT NULL,
ADD COLUMN     "vault_revision" BIGINT NOT NULL,
DROP COLUMN "id",
ADD COLUMN     "id" UUID NOT NULL,
ADD CONSTRAINT "users_pkey" PRIMARY KEY ("id");

-- DropTable
DROP TABLE "audit_logs";

-- DropTable
DROP TABLE "vaults";

-- CreateTable
CREATE TABLE "sessions" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "device_name" TEXT NOT NULL,
    "refresh_token_hash" BYTEA NOT NULL,
    "previous_refresh_token_hash" BYTEA,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "revoked_at" TIMESTAMPTZ(6),
    "revoke_reason" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_used_at" TIMESTAMPTZ(6),

    CONSTRAINT "sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "email_verifications" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "purpose" TEXT NOT NULL,
    "target_email" TEXT NOT NULL,
    "code_hash" BYTEA NOT NULL,
    "attempts" SMALLINT NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "consumed_at" TIMESTAMPTZ(6),

    CONSTRAINT "email_verifications_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_log" (
    "id" BIGSERIAL NOT NULL,
    "user_id" UUID NOT NULL,
    "session_id" UUID,
    "event_type" TEXT NOT NULL,
    "outcome" TEXT NOT NULL,
    "occurred_at" TIMESTAMPTZ(6) NOT NULL,
    "metadata" JSONB NOT NULL,
    "prev_hash" BYTEA,
    "hash" BYTEA NOT NULL,

    CONSTRAINT "audit_log_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_log_pii" (
    "id" BIGINT NOT NULL,
    "ip" INTEGER NOT NULL,
    "user_agent" TEXT NOT NULL,

    CONSTRAINT "audit_log_pii_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "vault_items" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "version" INTEGER NOT NULL,
    "revision" BIGINT NOT NULL,
    "nonce" BYTEA NOT NULL,
    "ciphertext" BYTEA NOT NULL,
    "deleted_at" TIMESTAMPTZ(6),
    "format_version" SMALLINT NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "vault_items_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "two_factor" (
    "user_id" UUID NOT NULL,
    "status" TEXT NOT NULL,
    "secret_ciphertext" BYTEA NOT NULL,
    "last_used_step" BIGINT,
    "activated_at" TIMESTAMPTZ(6),
    "secret_nonce" BYTEA NOT NULL,
    "server_key_id" SMALLINT NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "two_factor_pkey" PRIMARY KEY ("user_id")
);

-- CreateTable
CREATE TABLE "recovery_codes" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "code_hash" BYTEA NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "used_at" TIMESTAMPTZ(6),

    CONSTRAINT "recovery_codes_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "sessions_user_id_idx" ON "sessions"("user_id");

-- CreateIndex
CREATE INDEX "email_verifications_user_id_idx" ON "email_verifications"("user_id");

-- CreateIndex
CREATE INDEX "audit_log_user_id_occurred_at_idx" ON "audit_log"("user_id", "occurred_at");

-- CreateIndex
CREATE INDEX "audit_log_session_id_idx" ON "audit_log"("session_id");

-- CreateIndex
CREATE INDEX "vault_items_user_id_revision_idx" ON "vault_items"("user_id", "revision");

-- CreateIndex
CREATE INDEX "recovery_codes_user_id_idx" ON "recovery_codes"("user_id");

-- AddForeignKey
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "email_verifications" ADD CONSTRAINT "email_verifications_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "audit_log" ADD CONSTRAINT "audit_log_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "audit_log" ADD CONSTRAINT "audit_log_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "sessions"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "audit_log_pii" ADD CONSTRAINT "audit_log_pii_id_fkey" FOREIGN KEY ("id") REFERENCES "audit_log"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "vault_items" ADD CONSTRAINT "vault_items_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "two_factor" ADD CONSTRAINT "two_factor_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "recovery_codes" ADD CONSTRAINT "recovery_codes_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
