# End Security · Backend

API REST de **End Security**, un gestor de contraseñas móvil para Android con cifrado de **conocimiento cero** (*zero-knowledge*). El servidor autentica a los usuarios, sincroniza su bóveda cifrada y deja una bitácora de auditoría verificable, pero **nunca** recibe la contraseña maestra ni puede leer las contraseñas guardadas.

- **Producción:** `https://api.endsecurity.lat/api/health`
- **App Android:** repositorio `end-security-android`

## Modelo de conocimiento cero

Todo el cifrado ocurre en el teléfono. El servidor solo guarda texto cifrado y valores derivados que no sirven para descifrar nada.

1. La app deriva la **master key** con **Argon2id** a partir de la contraseña maestra (mínimo 64 MiB, 3 iteraciones, 1 hilo).
2. De la master key obtiene, con **HKDF-SHA256**, dos claves: la `auth_key`, que se envía como `authHash` para iniciar sesión, y la `enc_key`, que nunca sale del dispositivo.
3. La **clave de la bóveda** se cifra con la `enc_key` (AES-256-GCM) y se guarda en el servidor como `pvk`.
4. Cada elemento de la bóveda se cifra con la clave de la bóveda (AES-256-GCM). El `userId` forma parte de los datos autenticados, así que un elemento cifrado no puede moverse a otra cuenta.
5. El servidor vuelve a aplicar **Argon2id** sobre el `authHash` antes de guardarlo.

Si alguien obtuviera la base de datos completa, solo tendría blobs cifrados, hashes y registros de auditoría.

## Stack

| Capa | Tecnología |
| --- | --- |
| Framework | NestJS 11 · TypeScript 5 · Express |
| Base de datos | PostgreSQL · Prisma ORM 6.19 |
| Autenticación | JWT (HS256) · refresh tokens opacos · TOTP (`otplib`) |
| Criptografía | `argon2` (Argon2id) · `crypto` de Node (AES-256-GCM, HMAC-SHA256) |
| Seguridad HTTP | Helmet · `express-rate-limit` · `class-validator` |
| Correo | Resend |
| Despliegue | Railway |

## Módulos

| Módulo | Responsabilidad |
| --- | --- |
| `auth` | Registro, prelogin, login, refresh con rotación y gestión de sesiones |
| `email-verification` | Códigos de 6 dígitos para verificar el correo |
| `two-factor` | Verificación en dos pasos con TOTP y códigos de recuperación |
| `users` | Perfil del usuario |
| `account` | Cambio de contraseña maestra, cambio de correo y eliminación de la cuenta |
| `vault` | Sincronización de elementos cifrados con revisiones y rotación de la clave de la bóveda |
| `audit` | Bitácora encadenada con HMAC y verificación de su integridad |
| `mail` | Envío de correos transaccionales con Resend |

## Seguridad

- **Verificación de correo obligatoria** antes del primer inicio de sesión. Los códigos se guardan como HMAC, admiten 5 intentos y tienen tiempo de espera entre reenvíos.
- **2FA con TOTP:** secretos cifrados con AES-256-GCM y claves rotables, protección contra la reutilización de un código, bloqueo tras 5 fallos en 15 minutos y códigos de recuperación de un solo uso.
- **Tokens:** access tokens de 15 minutos con tipo explícito; refresh tokens opacos guardados como HMAC, rotados en cada uso, con revocación de la sesión si se detecta reúso.
- **Reautenticación** para operaciones sensibles: cambio de contraseña maestra, eliminación de la cuenta y desactivación del 2FA.
- **Límites de intentos:** límite general por IP, límite reforzado en `/api/auth` y bloqueo de la cuenta tras 5 fallos en 15 minutos.
- **Protección contra enumeración:** registrarse con un correo existente responde con un desafío señuelo idéntico al real.
- **Auditoría a prueba de manipulación:** cada evento se encadena con HMAC-SHA256 al anterior; los datos personales van en una tabla aparte.
- **Validación estricta:** DTOs que rechazan propiedades no declaradas y sin conversiones implícitas de tipos; errores sanitizados.
- **Configuración segura:** en producción el servidor no arranca con secretos débiles, de ejemplo o repetidos.
- **IP real del cliente:** solo se confía en el número de proxies indicado en `TRUST_PROXY`, para que cabeceras como `X-Forwarded-For` no puedan falsificarse (CWE-348).
- **Registros:** formato Syslog RFC 5424, una línea por petición, con la IP truncada a /24.

## Requisitos

- Node.js 22 o superior
- PostgreSQL 15 o superior
- Una cuenta de [Resend](https://resend.com) (opcional en desarrollo)

## Instalación local

```bash
git clone https://github.com/Diego-Zarate18/end-security-backend.git
cd end-security-backend
npm install
cp .env.example .env
```

Edita `.env`. Como mínimo necesitas `DATABASE_URL`, `JWT_SECRET`, `JWT_REFRESH_SECRET`, `AUDIT_HMAC_KEY` y `TOTP_ENCRYPTION_KEYS`. Genera los secretos así:

```bash
# JWT_SECRET, JWT_REFRESH_SECRET y AUDIT_HMAC_KEY (uno distinto para cada una)
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"

# TOTP_ENCRYPTION_KEYS
node -e "console.log('1:' + require('crypto').randomBytes(32).toString('base64'))"
```

Sin `RESEND_API_KEY`, en desarrollo los correos se escriben en la consola.

Aplica las migraciones y arranca:

```bash
npx prisma migrate deploy
npm run start:dev
```

La API queda en `http://localhost:3000/api`. Comprueba que responde en `http://localhost:3000/api/health`.

## Scripts

| Comando | Descripción |
| --- | --- |
| `npm run start:dev` | Servidor de desarrollo con recarga automática |
| `npm run build` | Genera el cliente de Prisma y compila a `dist/` |
| `npm run start:prod` | Ejecuta la versión compilada |
| `npm run migrate:deploy` | Aplica las migraciones pendientes |
| `npm run lint` | ESLint con corrección automática |
| `npm run format` | Prettier sobre `src/` |
| `npm test` | Pruebas unitarias con Jest |

Prueba de punta a punta con el mismo cifrado que la app (necesita `.env` y la base migrada):

```bash
npm run build && node scripts/e2e/flujo-completo.mjs
```

## Endpoints

Todas las rutas llevan el prefijo `/api`.

| Método | Ruta | Descripción | Auth |
| --- | --- | --- | --- |
| GET | `/health` | Estado del servicio y de la base | No |
| POST | `/auth/prelogin` | Parámetros KDF de la cuenta | No |
| POST | `/auth/register` | Registro | No |
| POST | `/auth/email/verify/confirm` | Confirma el código del correo | Desafío |
| POST | `/auth/email/verify/resend` | Reenvía el código | Desafío |
| POST | `/auth/login` | Inicio de sesión | No |
| POST | `/auth/2fa/verify` | Completa el login con TOTP o código de recuperación | Desafío |
| POST | `/auth/refresh` | Rota el refresh token | Refresh |
| POST | `/auth/logout` | Cierra la sesión actual | Bearer |
| GET | `/auth/sessions` | Sesiones activas | Bearer |
| DELETE | `/auth/sessions/:id` | Revoca una sesión | Bearer |
| POST | `/auth/sessions/revoke-others` | Revoca las demás sesiones | Bearer |
| GET | `/auth/2fa` | Estado del 2FA | Bearer |
| POST | `/auth/2fa/setup` | Secreto TOTP y código QR | Bearer |
| POST | `/auth/2fa/activate` | Activa el 2FA | Bearer |
| POST | `/auth/2fa/disable` | Desactiva el 2FA | Bearer |
| POST | `/auth/2fa/recovery-codes` | Regenera los códigos de recuperación | Bearer |
| POST | `/auth/password` | Cambia la contraseña maestra | Bearer |
| POST | `/auth/email/change` | Solicita el cambio de correo | Bearer |
| POST | `/auth/email/change/confirm` | Confirma el correo nuevo | Bearer |
| GET | `/users/me` | Perfil | Bearer |
| PATCH | `/users/me` | Edita el perfil | Bearer |
| DELETE | `/users/me` | Elimina la cuenta | Bearer |
| GET | `/vault/sync` | Descarga cambios de la bóveda | Bearer |
| POST | `/vault/sync` | Sube elementos cifrados | Bearer |
| POST | `/vault/rotate-key` | Rota la clave de la bóveda | Bearer |
| GET | `/audit` | Historial de eventos | Bearer |
| GET | `/audit/verify` | Verifica la cadena de auditoría | Bearer |

## Despliegue

El servicio corre en Railway con PostgreSQL en la red privada del proyecto. Cada push a `main` despliega automáticamente: compila con `npm run build`, aplica las migraciones con `npm run migrate:deploy` y arranca con `npm run start:prod`, usando `/api/health` como healthcheck.

La guía paso a paso, con variables, dominio y correo, está en [`docs/despliegue.md`](docs/despliegue.md).

## Estructura

```text
├── prisma/
│   ├── schema.prisma
│   └── migrations/
├── scripts/e2e/          # Prueba de punta a punta por HTTP
├── docs/                 # Guía de despliegue
└── src/
    ├── common/           # Decoradores, filtros, interceptores, syslog, utilidades y validadores
    ├── config/           # Validación de variables de entorno
    ├── database/         # Servicio de Prisma
    ├── modules/          # auth, email-verification, two-factor, users, account, vault, audit, mail
    └── main.ts           # Helmet, CORS, límites, ValidationPipe y prefijo /api
```

## Equipo

- Diego Alberto Zárate Vázquez
- Brian Luis Ruiz Pérez

Proyecto de la asignatura Seguridad Informática · Ingeniería en Tecnologías de la Información e Innovación Digital · Universidad Politécnica de Chiapas.

## Licencia

[MIT](LICENSE)
