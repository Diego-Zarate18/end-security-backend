// Prueba de punta a punta por HTTP contra el backend local (tarea 32, fase 6 de la app End Security).
//
// Uso (desde la raíz del backend, con .env y la base migrada):
//   npm run build && node scripts/e2e/flujo-completo.mjs
//
// Arranca `node dist/main` en el puerto E2E_PORT (3999 por defecto) con límites de intentos altos para no esperar,
// lee los códigos de verificación de su consola (sin RESEND_API_KEY los correos van a la consola) y recorre los 12 pasos.
// Los pasos 11 y 12 (cuentas sin verificar vencidas) envejecen la fila con Prisma, porque no se puede esperar 24 h.
// Usa el mismo cifrado que la app: Argon2id v1.3 → master_key; HKDF-SHA256 sin sal → enc_key / auth_key;
// pvk = AES-256-GCM(enc_key, vault_key, AAD "end-security/vault-key|userId|keyVersion");
// elemento = AES-256-GCM(vault_key, json, AAD "id|userId|formatVersion"). Sin secretos versionados: todo es aleatorio.
import { spawn } from 'node:child_process';
import {
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  randomBytes,
  randomUUID,
} from 'node:crypto';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const argon2 = require('argon2');
const { generate } = require('otplib');
const { PrismaClient } = require('@prisma/client');

const PORT = Number(process.env.E2E_PORT ?? 3999);
const BASE = `http://127.0.0.1:${PORT}/api`;
const KDF = { memoryKib: 65536, iterations: 3, parallelism: 1 };

// ---- Cifrado (igual que core/crypto de la app) ----

async function deriveKeys(password, salt, kdf = KDF) {
  const master = await argon2.hash(
    Buffer.from(password.normalize('NFKC'), 'utf8'),
    {
      type: argon2.argon2id,
      version: 0x13,
      memoryCost: kdf.memoryKib,
      timeCost: kdf.iterations,
      parallelism: kdf.parallelism,
      hashLength: 32,
      salt,
      raw: true,
    },
  );
  const hkdf = (info) =>
    Buffer.from(
      hkdfSync(
        'sha256',
        master,
        Buffer.alloc(0),
        Buffer.from(info, 'ascii'),
        32,
      ),
    );
  return {
    encKey: hkdf('end-security/enc'),
    authKey: hkdf('end-security/auth'),
  };
}

function seal(key, plaintext, aad) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from(aad, 'ascii'));
  const ciphertext = Buffer.concat([
    cipher.update(plaintext),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  return {
    nonce: nonce.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}

function open(key, sealed, aad) {
  const body = Buffer.from(sealed.ciphertext, 'base64');
  const decipher = createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(sealed.nonce, 'base64'),
  );
  decipher.setAAD(Buffer.from(aad, 'ascii'));
  decipher.setAuthTag(body.subarray(body.length - 16));
  return Buffer.concat([
    decipher.update(body.subarray(0, body.length - 16)),
    decipher.final(),
  ]);
}

const pvkAad = (userId, keyVersion) =>
  `end-security/vault-key|${userId}|${keyVersion}`;
const itemAad = (id, userId, formatVersion) =>
  `${id}|${userId}|${formatVersion}`;

// ---- Servidor y HTTP ----

let serverLog = '';
function startServer() {
  const child = spawn(process.execPath, ['dist/main'], {
    env: {
      ...process.env,
      PORT: String(PORT),
      AUTH_THROTTLE_LIMIT: '1000',
      THROTTLE_LIMIT: '5000',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (d) => (serverLog += d));
  child.stderr.on('data', (d) => (serverLog += d));
  return child;
}

async function waitFor(check, what, ms = 30_000) {
  const until = Date.now() + ms;
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() > until)
      throw new Error(`Tiempo agotado esperando: ${what}`);
    await new Promise((r) => setTimeout(r, 250));
  }
}

/** El último código de 6 dígitos enviado a `email` (línea [MailDev] de la consola del backend). */
async function codeFor(email, after) {
  return waitFor(() => {
    const chunk = serverLog.slice(after);
    const at = chunk.lastIndexOf(`Para: ${email}`);
    return at >= 0 ? /(\d{6}) es tu código/.exec(chunk.slice(at))?.[1] : null;
  }, `código para ${email}`);
}

async function api(method, path, { body, token, expect } = {}) {
  const res = await fetch(BASE + path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  const json = text ? JSON.parse(text) : null;
  if (expect !== undefined && res.status !== expect) {
    throw new Error(
      `${method} ${path}: se esperaba ${expect} y llegó ${res.status} ${json?.error ?? ''}`,
    );
  }
  return { status: res.status, data: json?.data, error: json };
}

// Prisma no lee el .env como el backend (Nest): se carga aquí si DATABASE_URL no viene del entorno.
if (!process.env.DATABASE_URL) process.loadEnvFile('.env');
const db = new PrismaClient();
const DAY_MS = 24 * 3_600_000;

const results = [];
async function step(name, fn) {
  const started = Date.now();
  try {
    const detail = await fn();
    results.push({ name, ok: true, detail, ms: Date.now() - started });
    console.log(`OK    ${name}${detail ? ` — ${detail}` : ''}`);
  } catch (error) {
    results.push({ name, ok: false, detail: error.message });
    console.log(`FALLA ${name} — ${error.message}`);
    throw error;
  }
}

// ---- Flujo ----

async function main() {
  const server = startServer();
  try {
    await waitFor(
      async () => (await fetch(`${BASE}/health`).catch(() => null))?.ok,
      'arranque del backend',
    );

    const userId = randomUUID();
    let email = `e2e+${randomBytes(4).toString('hex')}@example.com`;
    let password = `e2e-${randomBytes(12).toString('base64url')}`;
    let salt = randomBytes(16);
    let keyVersion = 1;
    const vaultKey = randomBytes(32);
    let keys = await deriveKeys(password, salt);
    let pvk = seal(keys.encKey, vaultKey, pvkAad(userId, keyVersion));
    let access;
    let recovery = [];
    let totpSecret;

    const login = async (secondFactor) => {
      const pre = await api('POST', '/auth/prelogin', {
        body: { email },
        expect: 200,
      });
      const k = await deriveKeys(
        password,
        Buffer.from(pre.data.kdf.salt, 'base64'),
        pre.data.kdf,
      );
      const res = await api('POST', '/auth/login', {
        body: {
          email,
          authHash: k.authKey.toString('base64'),
          deviceName: 'e2e',
        },
        expect: 200,
      });
      let auth = res.data;
      if (auth.requires2FA) {
        auth = (
          await api('POST', '/auth/2fa/verify', {
            body: { challengeToken: auth.challengeToken, ...secondFactor() },
            expect: 200,
          })
        ).data;
      }
      const opened = open(
        k.encKey,
        auth.keys.pvk,
        pvkAad(auth.user.id, auth.keys.keyVersion),
      );
      if (!opened.equals(vaultKey))
        throw new Error('la pvk no abre con la misma vault_key');
      access = auth.tokens.accessToken;
      return auth;
    };

    await step('1. Registro con el userId de la app', async () => {
      const res = await api('POST', '/auth/register', {
        body: {
          userId,
          email,
          authHash: keys.authKey.toString('base64'),
          kdf: { salt: salt.toString('base64'), ...KDF },
          pvk,
          deviceName: 'e2e',
        },
        expect: 201,
      });
      globalThis.challenge = res.data.challengeToken;
      return `requiresEmailVerification=${res.data.requiresEmailVerification}`;
    });

    await step('2. Verificación con el código de la consola', async () => {
      const code = await codeFor(email, 0);
      const res = await api('POST', '/auth/email/verify/confirm', {
        body: { challengeToken: globalThis.challenge, code },
        expect: 200,
      });
      if (res.data.user.id !== userId)
        throw new Error('el servidor cambió el userId');
      return `userId conservado, keyVersion=${res.data.keys.keyVersion}`;
    });

    await step('3. Login y la pvk abre en el cliente', async () => {
      await login();
      return 'tokens y vault_key correctos';
    });

    const itemId = randomUUID();
    await step('4. Crear, editar y borrar un elemento', async () => {
      const put = (baseVersion, title) => {
        const s = seal(
          vaultKey,
          Buffer.from(JSON.stringify({ title })),
          itemAad(itemId, userId, 1),
        );
        return api('POST', '/vault/sync', {
          token: access,
          body: {
            items: [{ id: itemId, baseVersion, formatVersion: 1, ...s }],
          },
          expect: 200,
        });
      };
      await put(0, 'creado');
      await put(1, 'editado');
      const pulled = await api('GET', '/vault/sync?since=0', {
        token: access,
        expect: 200,
      });
      const item = pulled.data.items.find((i) => i.id === itemId);
      const title = JSON.parse(
        open(vaultKey, item, itemAad(itemId, userId, 1)),
      ).title;
      if (title !== 'editado') throw new Error('el elemento no quedó editado');
      await api('POST', '/vault/sync', {
        token: access,
        body: { items: [{ id: itemId, baseVersion: 2, deleted: true }] },
        expect: 200,
      });
      const after = await api('GET', '/vault/sync?since=1', {
        token: access,
        expect: 200,
      });
      if (!after.data.items.find((i) => i.id === itemId)?.deleted)
        throw new Error('no quedó la lápida');
      return 'versiones 1 → 2 → 3 (lápida), el servidor solo ve bloques';
    });

    await step('5. Conflicto de versión', async () => {
      const id = randomUUID();
      const s = () => seal(vaultKey, Buffer.from('{}'), itemAad(id, userId, 1));
      await api('POST', '/vault/sync', {
        token: access,
        body: { items: [{ id, baseVersion: 0, formatVersion: 1, ...s() }] },
        expect: 200,
      });
      await api('POST', '/vault/sync', {
        token: access,
        body: { items: [{ id, baseVersion: 1, formatVersion: 1, ...s() }] },
        expect: 200,
      });
      const stale = await api('POST', '/vault/sync', {
        token: access,
        body: { items: [{ id, baseVersion: 1, formatVersion: 1, ...s() }] },
        expect: 409,
      });
      const conflict = stale.error.details.conflicts[0];
      return `409 ${stale.error.error}: ${conflict.reason}, currentVersion=${conflict.currentVersion}`;
    });

    await step(
      '6. Activar 2FA y entrar con TOTP y con código de respaldo',
      async () => {
        const setup = await api('POST', '/auth/2fa/setup', {
          token: access,
          body: { authHash: keys.authKey.toString('base64') },
          expect: 200,
        });
        totpSecret = setup.data.secret;
        const activated = await api('POST', '/auth/2fa/activate', {
          token: access,
          body: { code: await generate({ secret: totpSecret }) },
          expect: 200,
        });
        recovery = activated.data.recoveryCodes;
        await api('POST', '/auth/logout', { token: access, expect: 204 });
        // El mismo paso de 30 s no se acepta dos veces: se espera al siguiente
        await new Promise((r) =>
          setTimeout(r, (30 - (Math.floor(Date.now() / 1000) % 30) + 1) * 1000),
        );
        const code = await generate({ secret: totpSecret });
        await login(() => ({ code }));
        await api('POST', '/auth/logout', { token: access, expect: 204 });
        await login(() => ({ recoveryCode: recovery.shift() }));
        return `10 códigos 5-5 (p. ej. ${'x'.repeat(5)}-${'x'.repeat(5)}), TOTP y respaldo aceptados`;
      },
    );

    await step('7. Cambiar la contraseña maestra', async () => {
      const newPassword = `e2e-${randomBytes(12).toString('base64url')}`;
      const newSalt = randomBytes(16);
      const newKeys = await deriveKeys(newPassword, newSalt);
      const res = await api('POST', '/auth/password', {
        token: access,
        body: {
          currentAuthHash: keys.authKey.toString('base64'),
          newAuthHash: newKeys.authKey.toString('base64'),
          kdf: { salt: newSalt.toString('base64'), ...KDF },
          pvk: seal(newKeys.encKey, vaultKey, pvkAad(userId, keyVersion + 1)),
          code: recovery.shift(),
          expectedKeyVersion: keyVersion,
        },
        expect: 200,
      });
      keyVersion = res.data.keyVersion;
      password = newPassword;
      salt = newSalt;
      keys = newKeys;
      await login(() => ({ recoveryCode: recovery.shift() }));
      return `keyVersion=${keyVersion}, la contraseña nueva abre la misma vault_key`;
    });

    await step('8. Cambiar el correo', async () => {
      const newEmail = `e2e+${randomBytes(4).toString('hex')}@example.com`;
      const mark = serverLog.length;
      await api('POST', '/auth/email/change', {
        token: access,
        body: {
          newEmail,
          authHash: keys.authKey.toString('base64'),
          code: recovery.shift(),
        },
        expect: 202,
      });
      const code = await codeFor(newEmail, mark);
      const res = await api('POST', '/auth/email/change/confirm', {
        token: access,
        body: { code },
        expect: 200,
      });
      if (res.data.email !== newEmail) throw new Error('el correo no cambió');
      email = newEmail;
      const again = await api('POST', '/auth/email/change', {
        token: access,
        body: {
          newEmail: `e2e+${randomBytes(4).toString('hex')}@example.com`,
          authHash: keys.authKey.toString('base64'),
          code: recovery.shift(),
        },
      });
      return `cambiado; segundo intento → ${again.status} (24 h de espera, DEC-63)`;
    });

    await step('9. Cerrar sesiones', async () => {
      const current = access;
      await login(() => ({ recoveryCode: recovery.shift() }));
      const other = access;
      access = current;
      const list = await api('GET', '/auth/sessions', {
        token: access,
        expect: 200,
      });
      const revoked = await api('POST', '/auth/sessions/revoke-others', {
        token: access,
        expect: 200,
      });
      const dead = await api('GET', '/users/me', { token: other });
      return `${list.data.length} sesiones, ${revoked.data.revoked} cerradas, la otra responde ${dead.status}`;
    });

    await step('10. Eliminar la cuenta', async () => {
      await api('DELETE', '/users/me', {
        token: access,
        body: {
          authHash: keys.authKey.toString('base64'),
          code: recovery.shift(),
        },
        expect: 204,
      });
      const pre = await api('POST', '/auth/prelogin', {
        body: { email },
        expect: 200,
      });
      const k = await deriveKeys(
        password,
        Buffer.from(pre.data.kdf.salt, 'base64'),
        pre.data.kdf,
      );
      const res = await api('POST', '/auth/login', {
        body: {
          email,
          authHash: k.authKey.toString('base64'),
          deviceName: 'e2e',
        },
      });
      return `204; volver a entrar → ${res.status}`;
    });

    // Pasos 11 y 12: registro sobre un correo con cuenta sin verificar vencida, y sobre uno verificado
    const pw2 = `e2e-${randomBytes(12).toString('base64url')}`;
    const salt2 = randomBytes(16);
    const keys2 = await deriveKeys(pw2, salt2);
    const email2 = `e2e+${randomBytes(4).toString('hex')}@example.com`;
    const register2 = (id) =>
      api('POST', '/auth/register', {
        body: {
          userId: id,
          email: email2,
          authHash: keys2.authKey.toString('base64'),
          kdf: { salt: salt2.toString('base64'), ...KDF },
          pvk: seal(keys2.encKey, vaultKey, pvkAad(id, 1)),
          deviceName: 'e2e',
        },
        expect: 201,
      });
    const age = (id) =>
      db.users.update({
        where: { id },
        data: { created_at: new Date(Date.now() - DAY_MS - 3_600_000) },
      });
    const first = randomUUID();
    const second = randomUUID();

    await step(
      '11. Cuenta sin verificar vencida (24 h) se reemplaza al registrar',
      async () => {
        await register2(first);
        const mark = serverLog.length;
        await register2(randomUUID()); // vigente: señuelo, no se reemplaza
        if (
          !(
            await db.users.findUnique({ where: { id: first } })
          )?.email.startsWith('e2e+')
        )
          throw new Error('la cuenta vigente se tocó');
        await age(first);
        const res = await register2(second);
        const code = await codeFor(email2, mark);
        const verified = await api('POST', '/auth/email/verify/confirm', {
          body: { challengeToken: res.data.challengeToken, code },
          expect: 200,
        });
        const old = await db.users.findUnique({ where: { id: first } });
        if (verified.data.user.id !== second)
          throw new Error('el registro nuevo no quedó con su userId');
        if (!old?.anonymized_at || old.email === email2)
          throw new Error('la cuenta vieja no quedó anonimizada');
        return 'vigente no se toca; vencida se anonimiza y el correo queda libre';
      },
    );

    await step('12. Una cuenta verificada nunca se reemplaza', async () => {
      await age(second);
      await register2(randomUUID()); // 201 señuelo, igual que siempre
      const owner = await db.users.findUnique({ where: { email: email2 } });
      if (
        owner?.id !== second ||
        !owner.email_verified_at ||
        owner.anonymized_at
      )
        throw new Error('la cuenta verificada cambió');
      return 'tras 25 h sigue siendo la misma; el registro responde 201 señuelo';
    });
  } finally {
    await db.$disconnect();
    server.kill();
    const lines = serverLog.split('\n').filter((l) => /^<\d+>1 /.test(l));
    console.log(
      `\nSyslog: ${lines.length} líneas RFC 5424 del backend. Ejemplo:\n${lines.find((l) => l.includes(' login ')) ?? lines[0] ?? '(ninguna)'}`,
    );
    const failed = results.filter((r) => !r.ok).length;
    console.log(
      `\n${results.length - failed}/12 pasos bien${failed ? `, ${failed} con falla` : ''}.`,
    );
    process.exitCode = failed || results.length < 12 ? 1 : 0;
  }
}

main().catch(() => {
  process.exitCode = 1;
});
