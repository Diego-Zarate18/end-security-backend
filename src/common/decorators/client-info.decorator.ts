import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';

export interface ClientInfoData {
  ipAddress: string;
  userAgent: string;
}

export const ClientInfo = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): ClientInfoData => {
    const request = ctx.switchToHttp().getRequest<Request>();

    // request.ip ya respeta X-Forwarded-For solo para los proxies de confianza
    // configurados con TRUST_PROXY (main.ts). Leer el encabezado directamente
    // permitiría que cualquier cliente falsificara su IP en la auditoría.
    let ip = request.ip || request.socket.remoteAddress || '127.0.0.1';

    if (ip.startsWith('::ffff:')) {
      ip = ip.slice(7);
    }
    if (ip === '::1') {
      ip = '127.0.0.1';
    }

    const userAgent = (request.headers['user-agent'] || 'Unknown Device').slice(
      0,
      512,
    );

    return { ipAddress: ip, userAgent };
  },
);
