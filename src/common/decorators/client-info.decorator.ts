import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';

export interface ClientInfoData {
  ipAddress: string;
  userAgent: string;
}

export const ClientInfo = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): ClientInfoData => {
    const request = ctx.switchToHttp().getRequest<Request>();

    // Extraer IP considerando posibles proxies / balanceadores de carga
    const xForwardedFor = request.headers['x-forwarded-for'];
    let ip = '';

    if (typeof xForwardedFor === 'string') {
      ip = xForwardedFor.split(',')[0].trim();
    } else if (Array.isArray(xForwardedFor) && xForwardedFor.length > 0) {
      ip = xForwardedFor[0].trim();
    } else {
      ip = request.ip || request.socket.remoteAddress || '127.0.0.1';
    }

    // Normalizar IPv6 localhost
    if (ip === '::1' || ip === '::ffff:127.0.0.1') {
      ip = '127.0.0.1';
    }

    const userAgent = request.headers['user-agent'] || 'Unknown Device';

    return {
      ipAddress: ip,
      userAgent,
    };
  },
);

