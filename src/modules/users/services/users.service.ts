import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { randomUUID } from 'crypto';
import { PrismaService } from '../../../database/prisma.service';
import type { ClientInfoData } from '../../../common/decorators';
import { AuditEvent } from '../../audit/audit.constants';
import { AuditService } from '../../audit/services';
import { CreateUserData, UpdateProfileDto, UserResponseDto } from '../dto';
import { normalizeEmailText as normalizeEmail } from '../../auth/dto/normalize';

const withTwoFactor = {
  two_factor: { select: { status: true } },
} satisfies Prisma.usersInclude;

export type UserWithTwoFactor = Prisma.usersGetPayload<{
  include: typeof withTwoFactor;
}>;

/** Plazo para verificar el correo; pasado, otro registro con ese correo reemplaza a la cuenta. */
export const UNVERIFIED_TTL_MS = 24 * 3_600_000;

/** Fila anonimizada: se conserva por la cadena de auditoría y las FK, sin datos de la persona. */
export function anonymizedUserData(now: Date) {
  const empty = new Uint8Array(0);
  return {
    email: `deleted+${randomUUID()}@deleted.invalid`,
    display_name: 'Cuenta eliminada',
    // No es un hash PHC válido: ningún login puede coincidir
    auth_hash: '!deleted',
    kdf_salt: empty,
    pvk_ciphertext: empty,
    pvk_nonce: empty,
    email_verified_at: null,
    deleted_at: now,
    anonymized_at: now,
  } satisfies Prisma.usersUpdateManyMutationInput;
}

@Injectable()
export class UsersService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly auditService: AuditService,
  ) {}

  create(
    data: CreateUserData,
    tx: Prisma.TransactionClient = this.prisma,
  ): Promise<UserWithTwoFactor> {
    return tx.users.create({
      data: {
        id: data.id,
        email: normalizeEmail(data.email),
        display_name: data.displayName,
        marketing_opt_in: data.marketingOptIn,
        auth_hash: data.authHash,
        kdf_salt: data.kdfSalt,
        kdf_memory_kib: data.kdfMemoryKib,
        kdf_iterations: data.kdfIterations,
        kdf_parallelism: data.kdfParallelism,
        pvk_ciphertext: data.pvkCiphertext,
        pvk_nonce: data.pvkNonce,
        key_version: 1,
        vault_revision: 0n,
        purged_through_revision: 0n,
      },
      include: withTwoFactor,
    });
  }

  /**
   * Libera el correo de una cuenta que nunca se verificó en 24 h: la anonimiza
   * (sin tocar nada que no sea suya). Un solo UPDATE condicionado decide: una
   * cuenta verificada, con bóveda, eliminada o vigente no lo cumple y no se toca.
   * Devuelve si la reemplazó.
   */
  anonymizeIfExpiredUnverified(
    userId: string,
    client: ClientInfoData,
  ): Promise<boolean> {
    const now = new Date();
    return this.prisma.$transaction(async (tx) => {
      // INV-20: primero users (el UPDATE toma el candado), después lo demás
      const { count } = await tx.users.updateMany({
        where: {
          id: userId,
          email_verified_at: null,
          deleted_at: null,
          created_at: { lt: new Date(now.getTime() - UNVERIFIED_TTL_MS) },
          vault_items: { none: {} },
        },
        data: anonymizedUserData(now),
      });
      if (count === 0) return false;
      await this.auditService.record(
        {
          userId,
          event: AuditEvent.AccountDelete,
          outcome: 'success',
          metadata: { reason: 'unverified_expired' },
          client,
        },
        tx,
      );
      await tx.email_verifications.deleteMany({ where: { user_id: userId } });
      await tx.audit_log_pii.deleteMany({
        where: { audit_log: { user_id: userId } },
      });
      await tx.sessions.deleteMany({ where: { user_id: userId } });
      return true;
    });
  }

  /** Incluye cuentas eliminadas: el correo sigue reservado hasta anonimizarse. */
  findByEmail(email: string) {
    return this.prisma.users.findUnique({
      where: { email: normalizeEmail(email) },
      select: { id: true },
    });
  }

  findActiveByEmail(email: string): Promise<UserWithTwoFactor | null> {
    return this.prisma.users.findFirst({
      where: { email: normalizeEmail(email), deleted_at: null },
      include: withTwoFactor,
    });
  }

  findActiveByIdOrNull(id: string): Promise<UserWithTwoFactor | null> {
    return this.prisma.users.findFirst({
      where: { id, deleted_at: null },
      include: withTwoFactor,
    });
  }

  async findActiveById(id: string): Promise<UserWithTwoFactor> {
    const user = await this.prisma.users.findFirst({
      where: { id, deleted_at: null },
      include: withTwoFactor,
    });
    if (!user) {
      throw new NotFoundException('Usuario no encontrado.');
    }
    return user;
  }

  async getProfile(id: string): Promise<UserResponseDto> {
    return this.toProfile(await this.findActiveById(id));
  }

  async updateProfile(
    actor: { id: string; sessionId: string },
    dto: UpdateProfileDto,
    client: ClientInfoData,
  ): Promise<UserResponseDto> {
    const fields = Object.keys(dto).filter(
      (key) => dto[key as keyof UpdateProfileDto] !== undefined,
    );
    if (fields.length === 0) {
      throw new BadRequestException(
        'Envía displayName o marketingOptIn para actualizar.',
      );
    }
    await this.findActiveById(actor.id);
    const updated = await this.prisma.$transaction(async (tx) => {
      const user = await tx.users.update({
        where: { id: actor.id },
        data: {
          display_name: dto.displayName,
          marketing_opt_in: dto.marketingOptIn,
        },
        include: withTwoFactor,
      });
      await this.auditService.record(
        {
          userId: actor.id,
          sessionId: actor.sessionId,
          event: AuditEvent.AccountProfileUpdate,
          outcome: 'success',
          metadata: { fields: fields.join(',') },
          client,
        },
        tx,
      );
      return user;
    });
    return this.toProfile(updated);
  }

  toProfile(user: UserWithTwoFactor): UserResponseDto {
    return {
      id: user.id,
      email: user.email,
      displayName: user.display_name,
      marketingOptIn: user.marketing_opt_in,
      emailVerified: user.email_verified_at !== null,
      twoFactorEnabled: user.two_factor?.status === 'active',
      createdAt: user.created_at,
    };
  }
}
