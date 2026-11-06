/**
 * Catálogo cerrado de eventos de auditoría. Agregar un evento nuevo aquí
 * antes de registrarlo; nunca usar cadenas libres.
 */
export enum AuditEvent {
  AuthRegister = 'auth.register',
  AuthLogin = 'auth.login',
  AuthTwoFactorChallenge = 'auth.2fa_challenge',
  AuthRefreshReuse = 'auth.refresh_reuse',
  AuthLogout = 'auth.logout',
  VaultSyncPush = 'vault.sync_push',
  VaultSyncConflict = 'vault.sync_conflict',
  EmailVerifyRequest = 'email.verify_request',
  EmailVerifyConfirm = 'email.verify_confirm',
  EmailChangeRequest = 'email.change_request',
  EmailChangeConfirm = 'email.change_confirm',
  TwoFactorSetup = '2fa.setup',
  TwoFactorActivate = '2fa.activate',
  TwoFactorVerify = '2fa.verify',
  TwoFactorDisable = '2fa.disable',
  TwoFactorRecoveryRegenerate = '2fa.recovery_regenerate',
}

export type AuditOutcome = 'success' | 'failure';

/** Versión del formato canónico que entra al HMAC; cambiarla rompe la verificación de filas viejas. */
export const AUDIT_HASH_VERSION = 1;
