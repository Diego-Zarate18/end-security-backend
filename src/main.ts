import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { AppModule } from './app.module';
import { HttpExceptionFilter } from './common/filters';
import { TransformInterceptor } from './common/interceptors';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);

  // 1. Cabeceras HTTP de seguridad con Helmet
  app.use(helmet());

  // 2. Configuración estricta de CORS
  const corsOrigin = configService.get<string>('CORS_ORIGIN', '*');
  app.enableCors({
    origin: corsOrigin === '*' ? true : corsOrigin.split(','),
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    credentials: true,
  });

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
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  // 7. Filtro global de excepciones sanitizado
  app.useGlobalFilters(new HttpExceptionFilter());

  // 8. Interceptor global para estandarizar respuestas exitosas
  app.useGlobalInterceptors(new TransformInterceptor());

  const port = configService.get<number>('PORT', 3000);
  await app.listen(port);
  console.log(`[EndSecurityAPI] Servidor activo en http://localhost:${port}/api`);
}
bootstrap();
