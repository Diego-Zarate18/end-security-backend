import { plainToInstance } from 'class-transformer';
import {
  IsEnum,
  IsInt,
  IsNumber,
  Min,
  MinLength,
  IsOptional,
  IsString,
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

  if (validatedConfig.NODE_ENV === Environment.Production) {
    const placeholders = [
      validatedConfig.JWT_SECRET,
      validatedConfig.JWT_REFRESH_SECRET,
    ].some((secret) => secret.includes('change_in_production'));
    if (
      placeholders ||
      validatedConfig.JWT_SECRET === validatedConfig.JWT_REFRESH_SECRET
    ) {
      throw new Error(
        '[ConfigValidationError] En producción los secretos JWT deben ser propios y distintos entre sí.',
      );
    }
  }

  return validatedConfig;
}
