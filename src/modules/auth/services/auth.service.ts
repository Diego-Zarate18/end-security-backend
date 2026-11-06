import {
  ConflictException,
  Injectable,
  Logger,
  OnModuleInit,
  UnauthorizedException,
} from '@nestjs/common';
import * as argon2 from 'argon2';
import { randomBytes } from 'crypto';
import type { ClientInfoData } from '../../../common/decorators';
import { fromBase64, toBase64 } from '../../../common/utils';
import { PrismaService } from '../../../database/prisma.service';
import { AuditEvent } from '../../audit/audit.constants';
import { AuditService } from '../../audit/services';
import { EmailCodeService } from '../../email-verification/services';
import {
  UsersService,
  UserWithTwoFactor,
} from '../../users/services/users.service';
import { verifyAuthHash } from '../auth-hash';
import {
  DEFAULT_KDF_PARAMS,
  SERVER_ARGON2_OPTIONS,
  TokenType,
} from '../auth.constants';
import {
  AccountKeysDto,
  AuthResponseDto,
  EmailVerificationRequiredDto,
  KdfParamsResponseDto,
  LoginDto,
  PreloginDto,
  PreloginResponseDto,
  RegisterDto,
  ResendEmailCodeDto,
  TokenPairDto,
  TwoFactorChallengeDto,
  VerifyEmailDto,
} from '../dto';
import { SessionsService } from './sessions.service';
import { TokenService } from './token.service';

const invalidCredentials = () =>
  new UnauthorizedException('Credenciales inválidas.');

export type LoginResult =
  AuthResponseDto | TwoFactorChallengeDto | EmailVerificationRequiredDto;

@Injectable()
export class AuthService implements OnModuleInit {
  private readonly logger = new Logger(AuthService.name);
  /** Hash señuelo para igualar el tiempo de respuesta cuando el correo no existe. */
  private dummyHash = '';

  constructor(
    private readonly prisma: PrismaService,
    private readonly usersService: UsersService,
    private readonly sessionsService: SessionsService,
    private readonly tokenService: TokenService,
    private readonly auditService: AuditService,
    private readonly emailCodes: EmailCodeService,
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

  /**
   * Crea la cuenta sin sesión: el acceso empieza hasta verificar el correo con
   * el código que se envía aquí mismo.
   */
  async register(
    dto: RegisterDto,
    client: ClientInfoData,
  ): Promise<EmailVerificationRequiredDto> {
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

    const user = await this.prisma.$transaction(async (tx) => {
      const created = await this.usersService.create(
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
      await this.auditService.record(
        {
          userId: created.id,
          event: AuditEvent.AuthRegister,
          outcome: 'success',
          metadata: { deviceName: dto.deviceName },
          client,
        },
        tx,
      );
      return created;
    });

    return this.emailVerificationRequired(user, dto.deviceName, client);
  }

  async login(dto: LoginDto, client: ClientInfoData): Promise<LoginResult> {
    const user = await this.usersService.findActiveByEmail(dto.email);

    if (!user) {
      await verifyAuthHash(this.dummyHash, dto.authHash);
      // Sin user_id no hay cadena donde registrarlo: solo log del servidor, sin el correo
      this.logger.warn(
        `[auth.login] intento con correo inexistente desde ${client.ipAddress}`,
      );
      throw invalidCredentials();
    }

    if (!(await verifyAuthHash(user.auth_hash, dto.authHash))) {
      await this.auditService.recordSafely({
        userId: user.id,
        event: AuditEvent.AuthLogin,
        outcome: 'failure',
        metadata: { reason: 'invalid_credentials', deviceName: dto.deviceName },
        client,
      });
      throw invalidCredentials();
    }

    // Contraseña correcta pero correo sin verificar: no hay sesión
    if (!user.email_verified_at) {
      await this.auditService.record({
        userId: user.id,
        event: AuditEvent.AuthLogin,
        outcome: 'failure',
        metadata: { reason: 'email_not_verified', deviceName: dto.deviceName },
        client,
      });
      return this.emailVerificationRequired(user, dto.deviceName, client);
    }

    return this.completeLogin(user, dto.deviceName, client);
  }

  /** Confirma el correo con el código y, en el mismo paso, inicia la sesión. */
  async verifyEmail(
    dto: VerifyEmailDto,
    client: ClientInfoData,
  ): Promise<AuthResponseDto | TwoFactorChallengeDto> {
    const claims = this.tokenService.verifyChallenge(
      dto.challengeToken,
      TokenType.EmailVerificationPending,
    );
    const user = await this.usersService.findActiveById(claims.userId);
    if (user.email_verified_at) {
      throw new ConflictException(
        'Tu correo ya está verificado. Inicia sesión.',
      );
    }

    const actor = { userId: user.id, client };
    const entry = await this.emailCodes.check(actor, 'verify_email', dto.code);
    const now = new Date();

    await this.prisma.$transaction(async (tx) => {
      await this.emailCodes.consume(tx, entry.id, now);
      await tx.users.update({
        where: { id: user.id },
        data: { email_verified_at: now },
      });
      await this.auditService.record(
        {
          userId: user.id,
          event: AuditEvent.EmailVerifyConfirm,
          outcome: 'success',
          client,
        },
        tx,
      );
    });

    const verified = await this.usersService.findActiveById(user.id);
    return this.completeLogin(verified, claims.deviceName, client);
  }

  /** Reenvía el código (mínimo 60 s entre envíos). */
  async resendEmailCode(
    dto: ResendEmailCodeDto,
    client: ClientInfoData,
  ): Promise<EmailVerificationRequiredDto> {
    const claims = this.tokenService.verifyChallenge(
      dto.challengeToken,
      TokenType.EmailVerificationPending,
    );
    const user = await this.usersService.findActiveById(claims.userId);
    if (user.email_verified_at) {
      throw new ConflictException(
        'Tu correo ya está verificado. Inicia sesión.',
      );
    }
    const verification = await this.emailCodes.issue(
      { userId: user.id, client },
      'verify_email',
      user.email,
    );
    return {
      requiresEmailVerification: true,
      requires2FA: false,
      challengeToken: dto.challengeToken,
      verification,
    };
  }

  refresh(refreshToken: string, client: ClientInfoData): Promise<TokenPairDto> {
    return this.sessionsService.rotate(refreshToken, client);
  }

  async logout(
    userId: string,
    sessionId: string,
    client: ClientInfoData,
  ): Promise<void> {
    await this.sessionsService.revoke(sessionId, 'logout', userId);
    await this.auditService.record({
      userId,
      sessionId,
      event: AuditEvent.AuthLogout,
      outcome: 'success',
      client,
    });
  }

  /** Usado también por el módulo 2FA al completar el desafío TOTP. */
  buildAuthResponse(
    user: UserWithTwoFactor,
    tokens: TokenPairDto,
  ): AuthResponseDto {
    return {
      requiresEmailVerification: false,
      requires2FA: false,
      tokens,
      user: this.usersService.toProfile(user),
      keys: this.keysOf(user),
    };
  }

  /** Último paso común: desafío 2FA si está activo, o sesión nueva. */
  private async completeLogin(
    user: UserWithTwoFactor,
    deviceName: string,
    client: ClientInfoData,
  ): Promise<AuthResponseDto | TwoFactorChallengeDto> {
    if (user.two_factor?.status === 'active') {
      await this.auditService.record({
        userId: user.id,
        event: AuditEvent.AuthTwoFactorChallenge,
        outcome: 'success',
        metadata: { deviceName },
        client,
      });
      return {
        requiresEmailVerification: false,
        requires2FA: true,
        challengeToken: this.tokenService.signTwoFactorChallenge(
          user.id,
          deviceName,
        ),
      };
    }

    return this.startSession(user, deviceName, client);
  }

  /**
   * Crea la sesión del dispositivo y la registra en auditoría. Lo usan el
   * login, la verificación del correo y el segundo factor (2FA).
   */
  async startSession(
    user: UserWithTwoFactor,
    deviceName: string,
    client: ClientInfoData,
  ): Promise<AuthResponseDto> {
    const tokens = await this.prisma.$transaction(async (tx) => {
      const created = await this.sessionsService.create(
        user.id,
        deviceName,
        tx,
      );
      await this.auditService.record(
        {
          userId: user.id,
          sessionId: created.sessionId,
          event: AuditEvent.AuthLogin,
          outcome: 'success',
          metadata: { deviceName },
          client,
        },
        tx,
      );
      return created.tokens;
    });
    return this.buildAuthResponse(user, tokens);
  }

  /**
   * Envía (o reutiliza, si se pidió hace menos de 60 s) el código y devuelve
   * el desafío. Si el correo falla, igual se entrega el desafío para reenviar.
   */
  private async emailVerificationRequired(
    user: UserWithTwoFactor,
    deviceName: string,
    client: ClientInfoData,
  ): Promise<EmailVerificationRequiredDto> {
    const challengeToken = this.tokenService.signEmailVerificationChallenge(
      user.id,
      deviceName,
    );
    let verification: EmailVerificationRequiredDto['verification'];
    try {
      verification = await this.emailCodes.issue(
        { userId: user.id, client },
        'verify_email',
        user.email,
        'skip',
      );
    } catch {
      verification = {
        sentTo: '',
        codeSent: false,
        expiresAt: new Date(),
        resendAvailableInSeconds: 0,
      };
    }
    return {
      requiresEmailVerification: true,
      requires2FA: false,
      challengeToken,
      verification,
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
