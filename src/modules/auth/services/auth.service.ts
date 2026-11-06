import {
  ConflictException,
  Injectable,
  Logger,
  OnModuleInit,
  UnauthorizedException,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import * as argon2 from 'argon2';
import { randomBytes, randomUUID } from 'crypto';
import type { ClientInfoData } from '../../../common/decorators';
import { fromBase64, toBase64 } from '../../../common/utils';
import { PrismaService } from '../../../database/prisma.service';
import { AuditEvent } from '../../audit/audit.constants';
import { AuditService } from '../../audit/services';
import {
  CODE_TTL_MINUTES,
  EmailCodeService,
  invalidEmailCode,
  RESEND_COOLDOWN_SECONDS,
  resendTooSoon,
} from '../../email-verification/services';
import {
  MailService,
  maskEmail,
  registrationAttemptMail,
} from '../../mail/services';
import {
  UsersService,
  UserWithTwoFactor,
} from '../../users/services/users.service';
import { verifyAuthHash } from '../auth-hash';
import {
  DEFAULT_KDF_PARAMS,
  EMAIL_CHALLENGE_TTL_SECONDS,
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

const REGISTRATION_NOTICE_INTERVAL_MS = 60 * 60 * 1000;

const invalidCredentials = () =>
  new UnauthorizedException('Credenciales inválidas.');

export type LoginResult =
  AuthResponseDto | TwoFactorChallengeDto | EmailVerificationRequiredDto;

@Injectable()
export class AuthService implements OnModuleInit {
  private readonly logger = new Logger(AuthService.name);
  /** Hash señuelo para igualar el tiempo de respuesta cuando el correo no existe. */
  private dummyHash = '';
  /** Último reenvío simulado por desafío señuelo (registro con correo existente). */
  private readonly decoySends = new Map<string, number>();
  /** Último aviso de intento de registro enviado a cada dueño. */
  private readonly registrationNotices = new Map<string, number>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly usersService: UsersService,
    private readonly sessionsService: SessionsService,
    private readonly tokenService: TokenService,
    private readonly auditService: AuditService,
    private readonly emailCodes: EmailCodeService,
    private readonly mailService: MailService,
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
   * Crea la cuenta sin sesión: el acceso empieza al verificar el correo con el
   * código que se envía aquí mismo.
   *
   * Si el correo ya tiene cuenta responde exactamente igual (201 con un
   * desafío), pero el desafío es un señuelo que nunca se puede confirmar, y al
   * dueño le llega un aviso. Así el registro no revela qué correos existen.
   */
  async register(
    dto: RegisterDto,
    client: ClientInfoData,
  ): Promise<EmailVerificationRequiredDto> {
    // Se hashea en ambos caminos para que el tiempo de respuesta sea parecido
    const authHash = await argon2.hash(
      Buffer.from(fromBase64(dto.authHash)),
      SERVER_ARGON2_OPTIONS,
    );

    const existing = await this.usersService.findByEmail(dto.email);
    if (existing) {
      return this.registrationDecoy(existing.id, dto, client);
    }

    let user: UserWithTwoFactor;
    try {
      user = await this.prisma.$transaction(async (tx) => {
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
    } catch (error) {
      // Dos registros simultáneos con el mismo correo: el segundo recibe el señuelo
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        const owner = await this.usersService.findByEmail(dto.email);
        if (owner) return this.registrationDecoy(owner.id, dto, client);
      }
      throw error;
    }

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
    const user = await this.usersService.findActiveByIdOrNull(claims.userId);
    // Desafío señuelo (correo ya registrado): se comporta como un código incorrecto
    if (!user) throw invalidEmailCode();
    if (user.email_verified_at) {
      throw new ConflictException(
        'Tu correo ya está verificado. Inicia sesión.',
      );
    }

    const entry = await this.emailCodes.check(
      { userId: user.id, client },
      dto.code,
    );
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
    const user = await this.usersService.findActiveByIdOrNull(claims.userId);
    if (user?.email_verified_at) {
      throw new ConflictException(
        'Tu correo ya está verificado. Inicia sesión.',
      );
    }

    let verification: EmailVerificationRequiredDto['verification'];
    if (user) {
      verification = await this.emailCodes.issue(
        { userId: user.id, client },
        user.email,
      );
    } else {
      // Señuelo: mismo límite de 60 s y misma respuesta, sin enviar nada
      const last = this.decoySends.get(claims.userId) ?? 0;
      const waited = Math.floor((Date.now() - last) / 1000);
      if (waited < RESEND_COOLDOWN_SECONDS) {
        throw resendTooSoon(RESEND_COOLDOWN_SECONDS - waited);
      }
      this.trackDecoy(claims.userId);
      verification = this.decoyVerification(claims.maskedEmail);
    }

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
    const masked = maskEmail(user.email);
    const challengeToken = this.tokenService.signEmailVerificationChallenge(
      user.id,
      deviceName,
      masked,
    );
    let verification: EmailVerificationRequiredDto['verification'];
    try {
      verification = await this.emailCodes.issue(
        { userId: user.id, client },
        user.email,
        'skip',
      );
    } catch {
      verification = {
        sentTo: masked,
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

  /** Respuesta de registro para un correo que ya tiene cuenta (ver register). */
  private async registrationDecoy(
    ownerId: string,
    dto: RegisterDto,
    client: ClientInfoData,
  ): Promise<EmailVerificationRequiredDto> {
    await this.auditService.record({
      userId: ownerId,
      event: AuditEvent.AuthRegister,
      outcome: 'failure',
      metadata: { reason: 'email_taken' },
      client,
    });

    // Aviso al dueño, como mucho uno por hora para no llenarle la bandeja
    const lastNotice = this.registrationNotices.get(ownerId) ?? 0;
    if (Date.now() - lastNotice > REGISTRATION_NOTICE_INTERVAL_MS) {
      this.registrationNotices.set(ownerId, Date.now());
      try {
        await this.mailService.send({
          to: dto.email,
          ...registrationAttemptMail(),
          idempotencyKey: `register-attempt/${ownerId}/${Date.now()}`,
        });
      } catch {
        this.logger.warn('No se pudo enviar el aviso de intento de registro.');
      }
    }

    const decoyId = randomUUID();
    this.trackDecoy(decoyId);
    const masked = maskEmail(dto.email);
    return {
      requiresEmailVerification: true,
      requires2FA: false,
      challengeToken: this.tokenService.signEmailVerificationChallenge(
        decoyId,
        dto.deviceName,
        masked,
      ),
      verification: this.decoyVerification(masked),
    };
  }

  private decoyVerification(
    maskedEmail: string,
  ): EmailVerificationRequiredDto['verification'] {
    return {
      sentTo: maskedEmail,
      codeSent: true,
      expiresAt: new Date(Date.now() + CODE_TTL_MINUTES * 60_000),
      resendAvailableInSeconds: RESEND_COOLDOWN_SECONDS,
    };
  }

  /** Recuerda el último "envío" de un señuelo; olvida los que ya vencieron. */
  private trackDecoy(decoyId: string): void {
    const now = Date.now();
    for (const [id, at] of this.decoySends) {
      if (now - at > EMAIL_CHALLENGE_TTL_SECONDS * 1000)
        this.decoySends.delete(id);
    }
    this.decoySends.set(decoyId, now);
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
