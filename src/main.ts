import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { AppModule } from './app.module';
import { HttpExceptionFilter } from './common/filters';
import { validationPipeOptions } from './common/validation-pipe.options';
import { TransformInterceptor } from './common/interceptors';
import { Severity, syslog, syslogMiddleware } from './common/syslog/syslog';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  const configService = app.get(ConfigService);

  // 0. Proxies de confianza (Railway = 1) para que req.ip y el rate limit usen la IP real
  const trustProxy = configService.get<number>('TRUST_PROXY', 0);
  app.set('trust proxy', trustProxy);
  if (
    configService.get<string>('NODE_ENV') === 'production' &&
    trustProxy === 0
  ) {
    // No falla: solo avisa. Detrás de Railway, sin esto el límite por IP vería a todos como una sola IP
    syslog(
      Severity.Warning,
      'startup',
      {},
      'TRUST_PROXY=0 en producción: el límite por IP no verá la IP real (detrás de Railway debe ser 1)',
    );
  }

  // 0.05 Syslog RFC 5424 (DEC-62): antes de los límites, para registrar también sus 429
  app.use(syslogMiddleware);

  // 0.1 Límite del cuerpo JSON: lotes de sincronización de la bóveda (50 x 32 KiB en base64)
  app.useBodyParser('json', { limit: '3mb' });

  // 1. Cabeceras HTTP de seguridad con Helmet
  app.use(helmet());

  // 2. CORS estricto: la app es nativa y no lo necesita; sin orígenes, no se habilita
  const corsOrigin = configService.get<string>('CORS_ORIGIN', '');
  const origins = corsOrigin
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
  if (origins.length > 0) {
    app.enableCors({
      origin: origins.includes('*') ? true : origins,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
      credentials: true,
    });
  }

  // 3. Prefijo global para todos los endpoints
  app.setGlobalPrefix('api');

  // 4. Rate Limiting general para prevenir abusos
  const throttleTtl = configService.get<number>('THROTTLE_TTL', 60);
  const throttleLimit = configService.get<number>('THROTTLE_LIMIT', 100);
  app.use(
    rateLimit({
      windowMs: throttleTtl * 1000,
      limit: throttleLimit,
      standardHeaders: true,
      legacyHeaders: false,
      message: {
        statusCode: 429,
        error: 'TooManyRequests',
        message:
          'Has superado el límite de peticiones permitido. Por favor espera un momento.',
      },
    }),
  );

  // 5. Rate Limiting estricto para rutas de autenticación (fuerza bruta)
  const authLimit = configService.get<number>('AUTH_THROTTLE_LIMIT', 10);
  app.use(
    '/api/auth',
    rateLimit({
      windowMs: throttleTtl * 1000,
      limit: authLimit,
      standardHeaders: true,
      legacyHeaders: false,
      message: {
        statusCode: 429,
        error: 'TooManyRequests',
        message:
          'Demasiados intentos de autenticación. Por seguridad, espera un momento.',
      },
    }),
  );

  // 6. Validación global estricta de DTOs (bloquea parámetros no autorizados)
  app.useGlobalPipes(new ValidationPipe(validationPipeOptions));

  // 7. Filtro global de excepciones sanitizado
  app.useGlobalFilters(new HttpExceptionFilter());

  // 8. Interceptor global para estandarizar respuestas exitosas
  app.useGlobalInterceptors(new TransformInterceptor());

  const port = configService.get<number>('PORT', 3000);
  await app.listen(port);
  syslog(Severity.Notice, 'startup', {}, `API activa en el puerto ${port}`);
}
bootstrap().catch((error: unknown) => {
  // Falta un secreto, la BD no responde, etc.: el servicio no puede funcionar
  syslog(Severity.Crit, 'startup', {}, 'La API no pudo arrancar');
  console.error(error);
  process.exit(1);
});
