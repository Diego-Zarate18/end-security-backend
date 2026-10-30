import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as argon2 from 'argon2';
import { UsersService } from '../users/users.service';
import { AuthResponseDto, LoginDto, RegisterDto } from './dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async register(registerDto: RegisterDto): Promise<AuthResponseDto> {
    const existing = await this.usersService.findByEmail(registerDto.email);
    if (existing) {
      throw new ConflictException(
        'El correo electrónico ya se encuentra registrado.',
      );
    }

    // Hashear el hash derivado del cliente con Argon2 del lado del servidor (Defensa en profundidad)
    const serverPasswordHash = await argon2.hash(registerDto.passwordHash);

    const user = await this.usersService.create({
      email: registerDto.email,
      passwordHash: serverPasswordHash,
    });

    const payload = { sub: user.id, email: user.email };
    const accessToken = this.jwtService.sign(payload);

    return {
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        isTwoFactorEnabled: user.isTwoFactorEnabled,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      },
    };
  }

  async login(loginDto: LoginDto): Promise<AuthResponseDto> {
    const user = await this.usersService.findByEmail(loginDto.email);

    if (!user) {
      // Mensaje uniforme para prevenir ataques de enumeración de usuarios
      throw new UnauthorizedException('Credenciales inválidas.');
    }

    const isMatch = await argon2.verify(
      user.passwordHash,
      loginDto.passwordHash,
    );

    if (!isMatch) {
      throw new UnauthorizedException('Credenciales inválidas.');
    }

    // Si el usuario tiene 2FA activado, emite un token provisional para verificar el código TOTP
    if (user.isTwoFactorEnabled) {
      const tempToken = this.jwtService.sign(
        { sub: user.id, email: user.email, is2FAPending: true },
        { expiresIn: '5m' },
      );

      return {
        requires2FA: true,
        tempToken,
      };
    }

    // Flujo normal sin 2FA
    const payload = { sub: user.id, email: user.email };
    const accessToken = this.jwtService.sign(payload);

    return {
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        isTwoFactorEnabled: false,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      },
    };
  }
}

