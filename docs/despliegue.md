# Guía de despliegue (Railway + Resend + Spaceship)

Para alguien que nunca ha usado Railway. El servidor queda en **`https://api.endsecurity.lat`**, con correos desde **`End Security <no-reply@endsecurity.lat>`**.
Quien despliega es la persona del equipo (o Diego). Esta guía no necesita ninguna credencial tuya ni de Claude Code.

> **Reglas:** los secretos se generan en tu computadora y se pegan directo en Railway. **Nunca** copies los del `.env` local. Nunca los pegues en un chat, un commit o una captura.

## 1. Crear el proyecto, el servicio y la base
1. Entra a <https://railway.com>, inicia sesión con GitHub y elige **New Project → Deploy from GitHub repo**.
2. Elige `end-security-backend` y la rama que acuerden (`main` o `develop`).
3. En el mismo proyecto: **+ New → Database → Add PostgreSQL**.
4. El archivo `railway.json` del repositorio ya dice cómo compilar (`npm run build`), qué correr antes de cada despliegue (`npm run migrate:deploy`), cómo arrancar (`npm run start:prod`) y la ruta de salud (`/api/health`). No hay que escribirlo en el panel.

## 2. Variables del servicio
En el servicio del backend: **Variables → New Variable**. Solo nombres; el valor lo pones tú.

| Variable | Valor |
|---|---|
| `NODE_ENV` | `production` |
| `DATABASE_URL` | La **referencia** que da Railway a la base: `${{ Postgres.DATABASE_URL }}` (el nombre `Postgres` es el de tu servicio de base). |
| `TRUST_PROXY` | `1` (Railway pone un proxy delante; con `0` el límite por IP vería a todos como una sola IP). |
| `PORT` | **No la pongas**: Railway la inyecta. |
| `JWT_SECRET` | Secreto nuevo, abajo. |
| `JWT_REFRESH_SECRET` | Otro secreto nuevo, distinto del anterior. |
| `AUDIT_HMAC_KEY` | Otro secreto nuevo. Si luego se cambia, la cadena de auditoría ya registrada deja de verificarse. |
| `TOTP_ENCRYPTION_KEYS` | Una clave nueva con formato `1:<base64>`, abajo. |
| `RESEND_API_KEY` | La clave de Resend (`re_...`), del paso 5. |
| `EMAIL_FROM` | `End Security <no-reply@endsecurity.lat>` |
| `CORS_ORIGIN` | **Déjala vacía** (o no la pongas): la app es nativa y no usa CORS. `*` no se acepta en producción. |

**Generar los secretos** (en tu computadora, uno por cada variable, con Node instalado):

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
node -e "console.log('1:' + require('crypto').randomBytes(32).toString('base64'))"
```

La primera línea sirve para `JWT_SECRET`, `JWT_REFRESH_SECRET` y `AUDIT_HMAC_KEY` (ejecútala tres veces). La segunda es para `TOTP_ENCRYPTION_KEYS`.

**Si falta algo, el servidor se niega a arrancar** en producción y el log dice qué variable (sin mostrar valores): falta `RESEND_API_KEY` o `EMAIL_FROM`, un secreto de menos de 32 caracteres o con el valor de ejemplo, los dos JWT iguales, `TOTP_ENCRYPTION_KEYS` o `DATABASE_URL` ausentes, o `CORS_ORIGIN=*`. Con `TRUST_PROXY=0` en producción solo avisa en el log.

## 3. Migraciones
`railway.json` corre `npm run migrate:deploy` (`prisma migrate deploy`) **antes** de cada despliegue. Si prefieres hacerlo a mano la primera vez, desde tu computadora con la `DATABASE_URL` pública de Railway: `npx prisma migrate deploy`.

## 4. Dominio `api.endsecurity.lat`
1. En el servicio: **Settings → Networking → Custom Domain** → escribe `api.endsecurity.lat`.
2. Railway muestra un registro **CNAME** (nombre `api`, valor tipo `xxxx.up.railway.app`).
3. En Spaceship: dominio `endsecurity.lat` → **DNS** → agrega ese CNAME tal cual.
4. Espera a que Railway marque el dominio como válido y emita el certificado HTTPS (minutos, a veces más).

## 5. Resend (correo)
1. En <https://resend.com> → **Domains → Add Domain** → `endsecurity.lat`.
2. Resend muestra registros DNS (SPF, DKIM y otros). Pégalos **tal cual** en Spaceship → DNS.
3. Espera a que el dominio diga **Verified**.
4. **API Keys → Create API Key** (permiso de envío) y pégala en Railway como `RESEND_API_KEY`.

La app no envía ni configura nada de esto: el correo es del servidor.

## 6. Comprobar que funciona
1. Salud: abre `https://api.endsecurity.lat/api/health`. Debe responder `200` con `{"success":true,"data":{"status":"ok"}, ...}` y nada más. Si la base no contesta, responde `503`.
2. Correo real: registra una cuenta de prueba (desde la app, o con `curl`/`scripts/e2e/flujo-completo.mjs` apuntando al servidor) con un correo tuyo. El código de 6 dígitos debe **llegar a la bandeja**, no a la consola.
3. Logs: en Railway → **Deployments → View Logs** deben verse líneas syslog RFC 5424 (empiezan con `<133>1 ...`, una por petición) y `startup` al arrancar.

## 7. Costos y apagado
Railway cobra por uso (servicio y base, por tiempo y recursos). Para pausar después de la entrega: en el servicio **Settings → Danger → Remove Service** o quita el despliegue activo; la base se conserva aparte (bórrala también si ya no se necesita). Revisa **Usage** para saber cuánto va.

## 8. Si algo falla
- **El servicio no arranca:** mira el log de despliegue. Un `[ConfigValidationError]` dice qué variable falta o está mal.
- **Falla el build:** el log lo muestra; `npm run build` genera el cliente de Prisma solo. Si `nest` no se encuentra, Railway no instaló las dependencias de desarrollo: no pongas `NODE_ENV=production` como variable de **compilación**.
- **Migraciones:** `npx prisma migrate status` (con la `DATABASE_URL` pública) dice si falta alguna. Una migración fallida se resuelve con `npx prisma migrate resolve` solo si sabes qué pasó; ante la duda, restaura.
- **Restaurar la base:** en el servicio PostgreSQL de Railway, **Backups** (según el plan) permite restaurar un respaldo. Sin respaldos activos no hay forma de recuperar datos: actívalos antes de usar cuentas reales.
- **Correos que no llegan:** el dominio debe estar *Verified* en Resend; los logs del servidor muestran el fallo de envío.
