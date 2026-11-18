import type { NextFunction, Request, Response } from 'express';
import { randomUUID } from 'crypto';
import { isIPv4, isIPv6 } from 'net';
import { hostname } from 'os';

/**
 * Registro de operaciones con syslog RFC 5424 (DEC-62, docs/backend/README.md §5
 * de la app). Una línea por petición a stdout; Docker la manda a rsyslog.
 * Nunca lleva correos, llaves, tokens, códigos, sales, bloques ni cuerpos:
 * solo los campos de SdParams.
 */
export enum Severity {
  Crit = 2,
  Err = 3,
  Warning = 4,
  Notice = 5,
  Info = 6,
}

const FACILITY_LOCAL0 = 16;
const APP_NAME = 'endsec-api';
const SD_ID = 'endsec@32473';
const HOST = hostname().replace(/[^\x21-\x7e]/g, '') || '-';

export interface SdParams {
  req?: string;
  status?: number;
  code?: string;
  ms?: number;
  user?: string;
  sess?: string;
  ip?: string;
}

/** RFC 5424 §6.3.3: dentro de un PARAM-VALUE se escapan `"`, `\` y `]`. */
const escapeSd = (value: string) => value.replace(/["\\\]]/g, '\\$&');

export function formatSyslog(
  severity: Severity,
  msgid: string,
  params: SdParams,
  message: string,
  now = new Date(),
): string {
  const sd = Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== '')
    .map(([k, v]) => `${k}="${escapeSd(String(v))}"`)
    .join(' ');
  const pri = FACILITY_LOCAL0 * 8 + severity;
  const structured = sd ? `[${SD_ID} ${sd}]` : '-';
  const msg = message.replace(/[\r\n]+/g, ' ');
  return `<${pri}>1 ${now.toISOString()} ${HOST} ${APP_NAME} ${process.pid} ${msgid} ${structured} ${msg}`;
}

export function syslog(
  severity: Severity,
  msgid: string,
  params: SdParams,
  message: string,
): void {
  process.stdout.write(formatSyslog(severity, msgid, params, message) + '\n');
}

/** IP truncada: /24 en IPv4 y /48 en IPv6 (la completa solo vive en audit_log_pii). */
export function truncateIp(ip: string | undefined): string | undefined {
  if (!ip) return undefined;
  const plain =
    ip.startsWith('::ffff:') && isIPv4(ip.slice(7)) ? ip.slice(7) : ip;
  if (isIPv4(plain)) {
    return `${plain.split('.').slice(0, 3).join('.')}.0/24`;
  }
  if (isIPv6(plain)) {
    const [head, tail = ''] = plain.split('::');
    const left = head ? head.split(':') : [];
    const right = tail ? tail.split(':') : [];
    const groups = [
      ...left,
      ...Array<string>(8 - left.length - right.length).fill('0'),
      ...right,
    ];
    return `${groups.slice(0, 3).join(':')}::/48`;
  }
  return undefined;
}

/** Nombre corto de cada operación (MSGID). Lo que no está aquí sale como `http`. */
const OPERATIONS: Record<string, string> = {
  'POST /api/auth/prelogin': 'prelogin',
  'POST /api/auth/register': 'register',
  'POST /api/auth/login': 'login',
  'POST /api/auth/email/verify/confirm': 'email_verify',
  'POST /api/auth/email/verify/resend': 'email_resend',
  'POST /api/auth/refresh': 'refresh',
  'POST /api/auth/logout': 'logout',
  'GET /api/auth/sessions': 'sessions_list',
  'DELETE /api/auth/sessions/:id': 'session_revoke',
  'POST /api/auth/sessions/revoke-others': 'sessions_revoke_others',
  'GET /api/auth/2fa': '2fa_status',
  'POST /api/auth/2fa/setup': '2fa_setup',
  'POST /api/auth/2fa/activate': '2fa_activate',
  'POST /api/auth/2fa/verify': '2fa_verify',
  'POST /api/auth/2fa/disable': '2fa_disable',
  'POST /api/auth/2fa/recovery-codes': '2fa_recovery_codes',
  'POST /api/auth/password': 'password_change',
  'POST /api/auth/email/change': 'email_change',
  'POST /api/auth/email/change/confirm': 'email_change_confirm',
  'GET /api/users/me': 'account_get',
  'PATCH /api/users/me': 'account_update',
  'DELETE /api/users/me': 'account_delete',
  'GET /api/vault/sync': 'vault_pull',
  'POST /api/vault/sync': 'vault_push',
  'POST /api/vault/rotate-key': 'vault_rotate_key',
  'GET /api/audit': 'activity',
  'GET /api/audit/verify': 'audit_verify',
  'GET /api/health': 'health',
};

/** Operaciones exitosas que cambian la seguridad de la cuenta (notice). */
const SECURITY_CHANGES = new Set([
  'register',
  'email_verify',
  'login',
  '2fa_verify',
  'logout',
  'session_revoke',
  'sessions_revoke_others',
  '2fa_activate',
  '2fa_disable',
  '2fa_recovery_codes',
  'password_change',
  'email_change_confirm',
  'account_delete',
  'vault_rotate_key',
]);

export function severityFor(status: number, msgid: string): Severity {
  if (status >= 500) return Severity.Err;
  if (status >= 400) return Severity.Warning;
  return SECURITY_CHANGES.has(msgid) ? Severity.Notice : Severity.Info;
}

/** "InvalidCode" / "Bad Request" → "invalid_code" / "bad_request". */
export const toCode = (name: string) =>
  name
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .toLowerCase();

const REQUEST_ID = /^[A-Za-z0-9-]{1,64}$/;

/**
 * Middleware que escribe una línea al terminar cada petición. Va antes que
 * los límites de intentos y el guard, para que sus 429 y 401 también queden.
 */
export function syslogMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const started = process.hrtime.bigint();
  const header = req.header('x-request-id');
  const requestId = header && REQUEST_ID.test(header) ? header : randomUUID();

  res.on('finish', () => {
    const route = (req.route as { path?: string } | undefined)?.path;
    const msgid = (route && OPERATIONS[`${req.method} ${route}`]) || 'http';
    const user = req.user as { id?: string; sessionId?: string } | undefined;
    const errorCode = res.locals.errorCode as string | undefined;
    const status = res.statusCode;
    syslog(
      severityFor(status, msgid),
      msgid,
      {
        req: requestId,
        status,
        code: errorCode ?? (status === 429 ? 'rate_limited' : undefined),
        ms: Number((process.hrtime.bigint() - started) / 1_000_000n),
        user: user?.id,
        sess: user?.sessionId,
        ip: truncateIp(req.ip),
      },
      `${req.method} ${route ?? 'sin ruta'}`,
    );
  });
  next();
}
