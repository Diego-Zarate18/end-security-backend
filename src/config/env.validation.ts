import { plainToInstance, Transform } from 'class-transformer';
import { parseTotpKeys } from './totp-keys';
import {
  IsEnum,
  IsInt,
  IsNumber,
  Min,
  MinLength,
  IsOptional,
  IsString,
  Matches,
  validateSync,
} from 'class-validator';

enum Environment {
  Development = 'development',
  Production = 'production',
  Test = 'test',
}

export class EnvironmentVariables {
  @IsEnum(Environment)
  @IsOptional()
  NODE_ENV: Environment = Environment.Development;

  @IsNumber()
  @IsOptional()
  PORT: number = 3000;

  @IsString()
  DATABASE_URL: string;

  @IsString()
  @MinLength(32)
  JWT_SECRET: string;

  @IsString()
  @IsOptional()
  JWT_EXPIRES_IN: string = '15m';

  /** También se usa como pepper para el HMAC de los refresh tokens. */
  @IsString()
  @MinLength(32)
  JWT_REFRESH_SECRET: string;

  @IsString()
  @IsOptional()
  JWT_REFRESH_EXPIRES_IN: string = '7d';

  /** Clave del HMAC que encadena audit_log. Cambiarla invalida la verificación de lo ya registrado. */
  @IsString()
  @MinLength(32)
  AUDIT_HMAC_KEY: string;

  /** API key de Resend (re_...). Sin ella, en desarrollo los correos van a la consola. */
  @Transform(({ value }: { value: unknown }) =>
    value === '' ? undefined : value,
  )
  @Matches(/^re_[A-Za-z0-9_]+$/, {
    message: 'RESEND_API_KEY debe ser una API key de Resend (re_...).',
  })
  @IsOptional()
  RESEND_API_KEY?: string;

  /** Remitente; con onboarding@resend.dev solo se puede enviar al correo de tu cuenta Resend. */
  @IsString()
  @IsOptional()
  EMAIL_FROM: string = 'End Security <onboarding@resend.dev>';

  /** Claves AES-256 para cifrar los secretos TOTP: "1:<base64 de 32 bytes>". */
  @IsString()
  TOTP_ENCRYPTION_KEYS: string;

  @IsString()
  @IsOptional()
  TOTP_APP_NAME: string = 'End Security';

  @IsNumber()
  @IsOptional()
  THROTTLE_TTL: number = 60;

  @IsNumber()
  @IsOptional()
  THROTTLE_LIMIT: number = 100;

  @IsNumber()
  @IsOptional()
  AUTH_THROTTLE_LIMIT: number = 10;

  @IsString()
  @IsOptional()
  CORS_ORIGIN: string = 'http://localhost:3000';

  /** Número de proxies inversos de confianza delante de la API (Railway: 1). */
  @IsInt()
  @Min(0)
  @IsOptional()
  TRUST_PROXY: number = 0;
}

export function validateEnv(config: Record<string, unknown>) {
  const validatedConfig = plainToInstance(EnvironmentVariables, config, {
    enableImplicitConversion: true,
  });

  const errors = validateSync(validatedConfig, {
    skipMissingProperties: false,
  });

  if (errors.length > 0) {
    throw new Error(`[ConfigValidationError] ${errors.toString()}`);
  }

  try {
    parseTotpKeys(validatedConfig.TOTP_ENCRYPTION_KEYS);
  } catch (error) {
    throw new Error(`[ConfigValidationError] ${(error as Error).message}`);
  }

  if (validatedConfig.NODE_ENV === Environment.Production) {
    // Solo nombres de variables: nunca se imprime un valor
    const problems: string[] = [];
    if (!validatedConfig.RESEND_API_KEY) {
      problems.push(
        'RESEND_API_KEY es obligatoria (sin ella los correos no salen)',
      );
    }
    if (typeof config.EMAIL_FROM !== 'string' || !config.EMAIL_FROM.trim()) {
      problems.push(
        'EMAIL_FROM es obligatoria (remitente con dominio verificado)',
      );
    }
    const secrets = [
      validatedConfig.JWT_SECRET,
      validatedConfig.JWT_REFRESH_SECRET,
      validatedConfig.AUDIT_HMAC_KEY,
    ];
    if (
      secrets.some((secret) => secret.includes('change_in_production')) ||
      validatedConfig.JWT_SECRET === validatedConfig.JWT_REFRESH_SECRET
    ) {
      problems.push(
        'JWT_SECRET, JWT_REFRESH_SECRET y AUDIT_HMAC_KEY deben ser propios y distintos entre sí',
      );
    }
    if (config.CORS_ORIGIN === '*') {
      problems.push(
        'CORS_ORIGIN no puede ser * (la app es nativa: déjala vacía o pon un origen fijo)',
      );
    }
    if (problems.length > 0) {
      throw new Error(
        `[ConfigValidationError] En producción: ${problems.join('; ')}.`,
      );
    }
    // La app no usa CORS: sin valor explícito, en producción no se abre ningún origen
    if (config.CORS_ORIGIN === undefined) validatedConfig.CORS_ORIGIN = '';
  }

  return validatedConfig;
}
