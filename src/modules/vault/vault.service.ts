import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../../database/prisma.service';
import { SyncVaultDto, VaultResponseDto } from './dto';

@Injectable()
export class VaultService {
  constructor(private readonly prisma: PrismaService) {}

  async getVault(userId: string): Promise<VaultResponseDto> {
    const vault = await this.prisma.vault.findUnique({
      where: { userId },
    });

    if (!vault) {
      throw new NotFoundException(
        'No se ha encontrado ninguna bóveda para este usuario. Inicialice una nueva bóveda.',
      );
    }

    return {
      id: vault.id,
      userId: vault.userId,
      encryptedBlob: vault.encryptedBlob,
      salt: vault.salt,
      iv: vault.iv,
      version: vault.version,
      updatedAt: vault.updatedAt,
    };
  }

  async syncVault(
    userId: string,
    dto: SyncVaultDto,
  ): Promise<VaultResponseDto> {
    const currentVault = await this.prisma.vault.findUnique({
      where: { userId },
    });

    // Caso 1: Primera sincronización (creación inicial de la bóveda)
    if (!currentVault) {
      if (dto.version !== 1) {
        throw new BadRequestException(
          'La versión inicial de una nueva bóveda debe ser exactamente 1.',
        );
      }

      const newVault = await this.prisma.vault.create({
        data: {
          userId,
          encryptedBlob: dto.encryptedBlob,
          salt: dto.salt,
          iv: dto.iv,
          version: 1,
        },
      });

      return {
        id: newVault.id,
        userId: newVault.userId,
        encryptedBlob: newVault.encryptedBlob,
        salt: newVault.salt,
        iv: newVault.iv,
        version: newVault.version,
        updatedAt: newVault.updatedAt,
      };
    }

    // Caso 2: Bóveda existente (control de concurrencia optimista)
    const expectedVersion = currentVault.version + 1;

    if (dto.version !== expectedVersion) {
      throw new ConflictException(
        `Conflicto de sincronización: la versión enviada (${dto.version}) no coincide con la versión esperada (${expectedVersion}). Descargue la última versión de la bóveda antes de sobrescribir.`,
      );
    }

    const updatedVault = await this.prisma.vault.update({
      where: { userId },
      data: {
        encryptedBlob: dto.encryptedBlob,
        salt: dto.salt,
        iv: dto.iv,
        version: dto.version,
      },
    });

    return {
      id: updatedVault.id,
      userId: updatedVault.userId,
      encryptedBlob: updatedVault.encryptedBlob,
      salt: updatedVault.salt,
      iv: updatedVault.iv,
      version: updatedVault.version,
      updatedAt: updatedVault.updatedAt,
    };
  }
}

