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

Se maneja una estrategia **Multi-repo** (`end-security-android` y `end-security-backend`).

```text
src/
├── common/                   # DTOs globales, interceptores, guards (JWT, Throttler), decoradores
│   ├── decorators/
│   ├── filters/              # HttpExceptionFilter
│   ├── guards/               # JwtAuthGuard, RateLimitGuard
│   └── interceptors/         # LoggingInterceptor, AuditInterceptor
├── config/                   # Validación de variables de entorno
├── database/                 # PrismaService y PrismaModule
├── modules/                  # Módulos de dominio
│   ├── auth/                 # Registro, Login (Hash derivado), Refresh Token, TOTP 2FA
│   ├── users/                # Perfil y borrado de cuenta
│   ├── vault/                # Almacenamiento y sincronización de Bóveda Cifrada (GET/PUT)
│   └── audit-log/            # Registro de actividades e historial de logins
├── prisma/                   # schema.prisma y migraciones
├── app.module.ts
└── main.ts
```

---

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