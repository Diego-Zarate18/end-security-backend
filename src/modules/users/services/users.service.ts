import { Injectable, NotFoundException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../../database/prisma.service';
import { CreateUserData, UserResponseDto } from '../dto';

const withTwoFactor = {
  two_factor: { select: { status: true } },
} satisfies Prisma.usersInclude;

export type UserWithTwoFactor = Prisma.usersGetPayload<{
  include: typeof withTwoFactor;
}>;

const normalizeEmail = (email: string) => email.trim().toLowerCase();

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  create(
    data: CreateUserData,
    tx: Prisma.TransactionClient = this.prisma,
  ): Promise<UserWithTwoFactor> {
    return tx.users.create({
      data: {
        email: normalizeEmail(data.email),
        display_name: data.displayName,
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

  toProfile(user: UserWithTwoFactor): UserResponseDto {
    return {
      id: user.id,
      email: user.email,
      displayName: user.display_name,
      emailVerified: user.email_verified_at !== null,
      twoFactorEnabled: user.two_factor?.status === 'active',
      createdAt: user.created_at,
    };
  }
}
