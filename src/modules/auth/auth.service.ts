import {
  ConflictException,
  Injectable,
  OnModuleInit,
  UnauthorizedException,
} from '@nestjs/common';
import * as argon2 from 'argon2';
import { randomBytes } from 'crypto';
import { fromBase64, toBase64 } from '../../common/utils';
import { PrismaService } from '../../database/prisma.service';
import { UsersService, UserWithTwoFactor } from '../users/users.service';
import { DEFAULT_KDF_PARAMS, SERVER_ARGON2_OPTIONS } from './auth.constants';
import {
  AccountKeysDto,
  AuthResponseDto,
  KdfParamsResponseDto,
  LoginDto,
  PreloginDto,
  PreloginResponseDto,
  RegisterDto,
  TokenPairDto,
  TwoFactorChallengeDto,
} from './dto';
import { SessionsService, TokenService } from './services';

const invalidCredentials = () =>
  new UnauthorizedException('Credenciales inválidas.');

@Injectable()
export class AuthService implements OnModuleInit {
  /** Hash señuelo para igualar el tiempo de respuesta cuando el correo no existe. */
  private dummyHash = '';

  constructor(
    private readonly prisma: PrismaService,
    private readonly usersService: UsersService,
    private readonly sessionsService: SessionsService,
    private readonly tokenService: TokenService,
  ) {}

  async onModuleInit(): Promise<void> {
    this.dummyHash = await argon2.hash(randomBytes(32), SERVER_ARGON2_OPTIONS);
  }

  /**
   * Devuelve los parámetros KDF para que el cliente derive su master key.
   * Para correos inexistentes responde con parámetros por defecto y un salt
   * determinista, indistinguibles de una cuenta real.
   */
  async prelogin(dto: PreloginDto): Promise<PreloginResponseDto> {
    const user = await this.usersService.findActiveByEmail(dto.email);
    if (!user) {
      return {
        kdf: {
          salt: toBase64(this.tokenService.fakeKdfSalt(dto.email)),
          ...DEFAULT_KDF_PARAMS,
        },
      };
    }
    return { kdf: this.kdfOf(user) };
  }

  async register(dto: RegisterDto): Promise<AuthResponseDto> {
    const existing = await this.usersService.findByEmail(dto.email);
    if (existing) {
      throw new ConflictException(
        'El correo electrónico ya se encuentra registrado.',
      );
    }

    // Defensa en profundidad: el servidor vuelve a hashear el auth key del cliente
    const authHash = await argon2.hash(
      Buffer.from(fromBase64(dto.authHash)),
      SERVER_ARGON2_OPTIONS,
    );

    return this.prisma.$transaction(async (tx) => {
      const user = await this.usersService.create(
        {
          email: dto.email,
          displayName: dto.displayName,
          authHash,
          kdfSalt: fromBase64(dto.kdf.salt),
          kdfMemoryKib: dto.kdf.memoryKib,
          kdfIterations: dto.kdf.iterations,
          kdfParallelism: dto.kdf.parallelism,
          pvkCiphertext: fromBase64(dto.pvk.ciphertext),
          pvkNonce: fromBase64(dto.pvk.nonce),
        },
        tx,
      );
      const tokens = await this.sessionsService.create(
        user.id,
        dto.deviceName,
        tx,
      );
      return this.buildAuthResponse(user, tokens);
    });
  }

  async login(dto: LoginDto): Promise<AuthResponseDto | TwoFactorChallengeDto> {
    const user = await this.usersService.findActiveByEmail(dto.email);
    const presented = Buffer.from(fromBase64(dto.authHash));

    if (!user) {
      await argon2.verify(this.dummyHash, presented).catch(() => false);
      throw invalidCredentials();
    }

    const isMatch = await argon2
      .verify(user.auth_hash, presented)
      .catch(() => false);
    if (!isMatch) {
      throw invalidCredentials();
    }

    if (user.two_factor?.status === 'active') {
      return {
        requires2FA: true,
        challengeToken: this.tokenService.signTwoFactorChallenge(
          user.id,
          dto.deviceName,
        ),
      };
    }

    const tokens = await this.sessionsService.create(user.id, dto.deviceName);
    return this.buildAuthResponse(user, tokens);
  }

  refresh(refreshToken: string): Promise<TokenPairDto> {
    return this.sessionsService.rotate(refreshToken);
  }

  logout(userId: string, sessionId: string): Promise<void> {
    return this.sessionsService.revoke(sessionId, 'logout', userId);
  }

  /** Usado también por el módulo 2FA al completar el desafío TOTP. */
  buildAuthResponse(
    user: UserWithTwoFactor,
    tokens: TokenPairDto,
  ): AuthResponseDto {
    return {
      requires2FA: false,
      tokens,
      user: this.usersService.toProfile(user),
      keys: this.keysOf(user),
    };
  }

  private kdfOf(user: UserWithTwoFactor): KdfParamsResponseDto {
    return {
      salt: toBase64(user.kdf_salt),
      memoryKib: user.kdf_memory_kib,
      iterations: user.kdf_iterations,
      parallelism: user.kdf_parallelism,
    };
  }

  private keysOf(user: UserWithTwoFactor): AccountKeysDto {
    return {
      kdf: this.kdfOf(user),
      pvk: {
        ciphertext: toBase64(user.pvk_ciphertext),
        nonce: toBase64(user.pvk_nonce),
      },
      keyVersion: user.key_version,
    };
  }
}
