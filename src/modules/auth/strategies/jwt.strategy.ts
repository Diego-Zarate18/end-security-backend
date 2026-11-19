import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { TokenType } from '../auth.constants';
import { SessionsService } from '../services/sessions.service';

export interface JwtPayload {
  sub: string;
  sid?: string;
  typ?: TokenType;
}

/** Lo que queda disponible en `request.user` y en @CurrentUser(). */
export interface AuthenticatedUser {
  id: string;
  sessionId: string;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    configService: ConfigService,
    private readonly sessionsService: SessionsService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.getOrThrow<string>('JWT_SECRET'),
      algorithms: ['HS256'],
    });
  }

  async validate(payload: JwtPayload): Promise<AuthenticatedUser> {
    // Solo access tokens: el token de desafío 2FA no abre rutas protegidas
    if (payload?.typ !== TokenType.Access || !payload.sub || !payload.sid) {
      throw new UnauthorizedException('Token inválido o expirado.');
    }

    // Una sesión revocada (logout, robo de refresh token) invalida el access token al instante
    const active = await this.sessionsService.isActive(
      payload.sid,
      payload.sub,
    );
    if (!active) {
      throw new UnauthorizedException('La sesión ya no es válida.');
    }

    return { id: payload.sub, sessionId: payload.sid };
  }
}
