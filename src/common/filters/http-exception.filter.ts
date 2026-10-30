import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { Request, Response } from 'express';

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message: string | object = 'Ha ocurrido un error interno en el servidor.';
    let errorName = 'InternalServerError';

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const res = exception.getResponse();
      errorName = exception.name;

      if (typeof res === 'string') {
        message = res;
      } else if (typeof res === 'object' && res !== null) {
        const errorBody = res as Record<string, unknown>;
        message = (errorBody['message'] as string | object) || exception.message;
        errorName = (errorBody['error'] as string) || exception.name;
      }
    } else if (exception instanceof Prisma.PrismaClientKnownRequestError) {
      // Manejar errores conocidos de Prisma de forma segura sin filtrar nombres de columnas o SQL
      switch (exception.code) {
        case 'P2002': {
          status = HttpStatus.CONFLICT;
          errorName = 'ConflictError';
          const target = (exception.meta?.target as string[]) || [];
          const field = target.length > 0 ? target.join(', ') : 'recurso';
          message = `Ya existe un registro con ese valor de ${field}.`;
          break;
        }
        case 'P2025': {
          status = HttpStatus.NOT_FOUND;
          errorName = 'NotFoundError';
          message = 'El recurso solicitado no fue encontrado o no existe.';
          break;
        }
        default: {
          status = HttpStatus.BAD_REQUEST;
          errorName = 'DatabaseRequestError';
          message = 'Error en la solicitud de datos.';
          break;
        }
      }
      this.logger.warn(
        `[PrismaKnownError] ${exception.code} en ${request.method} ${request.url}: ${exception.message}`,
      );
    } else {
      // Error no controlado
      this.logger.error(
        `[UnhandledException] en ${request.method} ${request.url}:`,
        exception instanceof Error ? exception.stack : exception,
      );
    }

    response.status(status).json({
      statusCode: status,
      error: errorName,
      message,
      path: request.url,
      timestamp: new Date().toISOString(),
    });
  }
}

