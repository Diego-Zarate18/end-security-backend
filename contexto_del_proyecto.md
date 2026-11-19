# Contexto del Proyecto: End Security

## 1. Visión General del Proyecto
- **Nombre:** End Security (Gestor de contraseñas Móvil con Cifrado de Conocimiento Cero y Análisis Compuesto de Vulnerabilidades).
- **Materia / Ámbito:** Seguridad Informática (Ingeniería en Tecnologías de la Información e Innovación Digital - UP Chiapas).
- **Integrantes:** Zárate Vázquez Diego Alberto, Ruiz Pérez Brian Luis.
- **Objetivo Principal:** Crear un gestor de contraseñas nativo para Android y un backend en NestJS que garantice un modelo de **Conocimiento Cero (Zero-Knowledge)**. Si la base de datos del servidor es comprometida, el atacante solo obtendrá datos cifrados e indecodificables.

---

## 2. Arquitectura de Seguridad y Criptografía

### Modelo de Cero Conocimiento (Zero-Knowledge)
1. **Servidor Ciego:** El backend **NUNCA** recibe la contraseña maestra en texto plano ni las claves de descifrado.
2. **Derivación de Claves (Cliente - Android):**
   - **Argon2id:** Se usa para derivar la clave criptográfica a partir de la contraseña maestra en el teléfono.
   - **Android Keystore:** Almacena de forma segura la clave derivada con soporte opcional para autenticación biométrica (huella dactilar).
3. **Cifrado Simétrico:**
   - **AES-256-GCM:** La bóveda completa se cifra localmente en el dispositivo antes de transmitirse.
   - **Payload Cifrado (`encryptedBlob`):** El cliente envía al backend un JSON cifrado con su Vector de Inicialización (`iv`) y su `salt`.

### Integración de HIBP (Have I Been Pwned)
- **Método k-Anonymity:** Para verificar si una contraseña fue filtrada, el cliente genera el hash SHA-1 de la contraseña y envía **únicamente los primeros 5 caracteres** del hash a la API externa de HIBP.
- **Privacidad:** Las consultas a HIBP las realiza la aplicación Android directamente, sin pasar por el backend propio ni revelar la contraseña o el hash completo.

---

## 3. Stack Tecnológico

| Capa / Dominio | Tecnología / Herramienta | Uso en el Proyecto |
| :--- | :--- | :--- |
| **Frontend Móvil** | Kotlin, Jetpack Compose, Android Keystore, OkHttp | App nativa con consulta offline, biometría y Certificate Pinning. |
| **Backend API** | Node.js, NestJS (TypeScript), Express | API RESTful modular, validación de DTOs, Throttling. |
| **Base de Datos & ORM** | PostgreSQL, Prisma ORM | Persistencia de usuarios, auditoría y blobs cifrados. |
| **Autenticación** | JWT (Short-lived), TOTP (`otplib`) | Autenticación de sesiones y Verificación en 2 pasos (2FA). |
| **Despliegue / CI-CD** | Railway, GitHub Actions | Infraestructura cloud conectada al repositorio de GitHub. |
| **Herramientas de Seguridad** | OWASP ZAP, Semgrep, mitmproxy, `npm audit`, Android Lint | Pruebas de seguridad estáticas y dinámicas (Pentesting). |

---

## 4. Estructura del Repositorio del Backend (NestJS)

Se maneja una estrategia **Multi-repo** (`end-security-android` y `end-security-backend`). A continuación se describe la arquitectura modular del backend:

```text
end-security-backend/
├── prisma/
│   └── schema.prisma               # Modelado relacional (User, Vault, AuditLog)
├── src/
│   ├── common/                     # Componentes transversales y utilidades de seguridad
│   │   ├── decorators/             # @CurrentUser, @ClientInfo (IP/User-Agent), @Public
│   │   ├── dto/                    # DTOs globales (paginación, respuestas base)
│   │   ├── filters/                # Filtros de excepción globales (HttpExceptionFilter, PrismaExceptionFilter)
│   │   ├── guards/                 # Guards de seguridad y control de acceso (JwtAuthGuard, ThrottlerGuard)
│   │   ├── interceptors/           # Interceptors (Logging seguro, Transformación de respuestas)
│   │   └── middleware/             # Middlewares (Sanitización, Rate-limit, Client IP parser)
│   ├── config/                     # Configuración centralizada y validación de variables de entorno
│   │   ├── env.validation.ts       # Esquema estricto de variables (.env)
│   │   └── jwt.config.ts           # Configuración de expiración y secretos JWT
│   ├── database/                   # Capa de persistencia
│   │   ├── prisma.module.ts        # Módulo global exportable de Prisma
│   │   └── prisma.service.ts       # Servicio que gestiona el ciclo de vida de la conexión a PostgreSQL
│   ├── modules/                    # Módulos de dominio de la aplicación
│   │   ├── auth/                   # Autenticación, sesiones y emisión de tokens
│   │   │   ├── controllers/        # Endpoints /api/auth (register, login, refresh)
│   │   │   ├── services/           # Lógica de validación de credenciales con Argon2 y JWT
│   │   │   ├── strategies/         # Estrategias Passport (JwtStrategy)
│   │   │   ├── guards/             # Guards específicos de Auth
│   │   │   ├── dto/                # RegisterDto, LoginDto, TokenRefreshDto
│   │   │   └── auth.module.ts
│   │   ├── two-factor/             # Verificación en Dos Pasos (TOTP)
│   │   │   ├── controllers/        # Endpoints /api/auth/2fa (generate, enable, verify, disable)
│   │   │   ├── services/           # Gestión de secretos TOTP (otplib) y QR (qrcode)
│   │   │   ├── guards/             # TwoFactorGuard para operaciones sensibles
│   │   │   ├── dto/                # Verify2FaDto, Enable2FaDto
│   │   │   └── two-factor.module.ts
│   │   ├── users/                  # Gestión de perfil y cuenta de usuario
│   │   │   ├── controllers/        # Endpoints /api/users (perfil, eliminación de cuenta)
│   │   │   ├── services/           # Consultas sobre la entidad User
│   │   │   ├── dto/                # UpdateProfileDto, UserResponseDto
│   │   │   └── users.module.ts
│   │   ├── vault/                  # Bóveda Cifrada (Zero-Knowledge Sync)
│   │   │   ├── controllers/        # Endpoints /api/vault (obtención y sincronización del blob)
│   │   │   ├── services/           # Persistencia de blob, salt, IV y control de versiones
│   │   │   ├── dto/                # SyncVaultDto, VaultResponseDto
│   │   │   └── vault.module.ts
│   │   └── audit/                  # Registro y consulta de auditoría de seguridad
│   │       ├── controllers/        # Endpoints /api/audit (historial de accesos y eventos)
│   │       ├── services/           # Inserción asíncrona de eventos de seguridad (AuditLog)
│   │       ├── dto/                # AuditLogResponseDto, QueryAuditLogsDto
│   │       └── audit.module.ts
│   ├── app.controller.ts           # Health check / status endpoint (/api/health)
│   ├── app.module.ts               # Módulo raíz que integra la configuración y submódulos
│   ├── app.service.ts
│   └── main.ts                     # Punto de entrada (Helmet, CORS, ValidationPipe, GlobalPrefix: 'api')
├── .env.example                    # Plantilla de variables de entorno requeridas
├── nest-cli.json
├── package.json
└── tsconfig.json
```


## 5. Esquema de Base de Datos (`schema.prisma`)

```prisma
datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

generator client {
  provider = "prisma-client-js"
}

model User {
  id                 String      @id @default(uuid())
  email              String      @unique
  passwordHash       String      // Hash del login password (derivado en el cliente)
  isTwoFactorEnabled Boolean     @default(false)
  twoFactorSecret    String?     // Secreto TOTP
  createdAt          DateTime    @default(now())
  updatedAt          DateTime    @updatedAt

  vault              Vault?
  auditLogs          AuditLog[]

  @@map("users")
}

model Vault {
  id            String   @id @default(uuid())
  userId        String   @unique
  user          User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  encryptedBlob String   @db.Text // Contenido de la bóveda cifrado con AES-256-GCM
  salt          String   // Salt para Argon2id usado en el cliente
  iv            String   // Vector de Inicialización (IV) para AES-GCM
  version       Int      @default(1)
  updatedAt     DateTime @updatedAt

  @@map("vaults")
}

model AuditLog {
  id        String   @id @default(uuid())
  userId    String
  user      User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  action    String   // Ejemplos: "LOGIN_SUCCESS", "VAULT_SYNC", "2FA_ENABLED"
  ipAddress String
  userAgent String
  createdAt DateTime @default(now())

  @@map("audit_logs")
}
```

---

## 6. Módulo de Estadísticas y Análisis de Seguridad (Health Score)

Dado que la arquitectura es **Zero-Knowledge**, el servidor no puede leer los elementos guardados. Por lo tanto, **todo el procesamiento de métricas se ejecuta del lado del cliente (Android)** al desencriptar la bóveda en memoria:

1. **Fortaleza de Contraseñas:** Evaluación de entropía y patrones comunes de los passwords del usuario.
2. **Reuso de Credenciales:** Detección de contraseñas duplicadas entre diferentes sitios/servicios.
3. **Vulnerabilidades / Filtraciones:** Evaluación mediante HIBP (k-Anonymity) de las contraseñas almacenadas.
4. **Dashboard de Resumen:** La App Android compila estos 3 factores para calcular un índice general de "Salud de la Bóveda" (Vault Health Index).

---

## 7. Directrices de Desarrollo para el Agente / Asistente
- Priorizar la validación estricta de DTOs con `class-validator` en todos los endpoints REST.
- Asegurar que ningún log o respuesta de error exponga información sensible o detalles internos de la base de datos.
- Mantener la separación estricta de responsabilidades: el backend gestiona la sincronización del Blob cifrado, autenticación y auditoría; la App Android ejecuta el cifrado, descifrado y análisis de contraseñas.