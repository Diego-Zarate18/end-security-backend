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
  AuthSessionRevoke = 'auth.session_revoke',
  AuthSessionsRevokeOthers = 'auth.sessions_revoke_others',
  VaultSyncPush = 'vault.sync_push',
  VaultSyncConflict = 'vault.sync_conflict',
  VaultKeyRotation = 'vault.key_rotation',
  EmailVerifyRequest = 'email.verify_request',
  EmailVerifyConfirm = 'email.verify_confirm',
  TwoFactorSetup = '2fa.setup',
  TwoFactorActivate = '2fa.activate',
  TwoFactorVerify = '2fa.verify',
  TwoFactorDisable = '2fa.disable',
  TwoFactorRecoveryRegenerate = '2fa.recovery_regenerate',
  AccountProfileUpdate = 'account.profile_update',
  AccountPasswordChange = 'account.password_change',
  AccountDelete = 'account.delete',
}

export type AuditOutcome = 'success' | 'failure';

/** Versión del formato canónico que entra al HMAC; cambiarla rompe la verificación de filas viejas. */
export const AUDIT_HASH_VERSION = 1;
