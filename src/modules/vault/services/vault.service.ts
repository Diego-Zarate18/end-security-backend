import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { vault_items } from '@prisma/client';
import type { ClientInfoData } from '../../../common/decorators';
import { bigintToNumber, fromBase64, toBase64 } from '../../../common/utils';
import { PrismaService } from '../../../database/prisma.service';
import { AuditEvent } from '../../audit/audit.constants';
import { AuditService } from '../../audit/services';
import {
  PushVaultChangesDto,
  VaultConflictDto,
  VaultItemDto,
  VaultPushResponseDto,
  VaultSyncResponseDto,
} from '../dto';

/**
 * Sincronización Zero-Knowledge por elemento.
 *
 * - Cada lote aceptado incrementa `users.vault_revision` y todos sus elementos
 *   quedan marcados con esa revisión; el cliente usa la revisión como cursor.
 * - `version` de cada elemento implementa control de concurrencia optimista.
 * - Los borrados son tombstones (deleted_at) sin ciphertext, para que otros
 *   dispositivos se enteren; se purgan después y se registra el límite en
 *   `users.purged_through_revision`.
 */
type VaultChange = PushVaultChangesDto['items'][number] & { id: string };

@Injectable()
export class VaultService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly auditService: AuditService,
  ) {}

  async getChanges(
    userId: string,
    since: number,
  ): Promise<VaultSyncResponseDto> {
    const user = await this.prisma.users.findFirst({
      where: { id: userId, deleted_at: null },
      select: { vault_revision: true, purged_through_revision: true },
    });
    if (!user) {
      throw new NotFoundException('Usuario no encontrado.');
    }

    const cursor = BigInt(since);
    // Resincronización completa si el cliente parte de cero, si los tombstones
    // que necesitaría ya se purgaron, o si su cursor es inconsistente.
    const fullResync =
      cursor === 0n ||
      cursor < user.purged_through_revision ||
      cursor > user.vault_revision;

    const items = await this.prisma.vault_items.findMany({
      where: fullResync
        ? { user_id: userId, deleted_at: null }
        : { user_id: userId, revision: { gt: cursor } },
      orderBy: { revision: 'asc' },
    });

    return {
      revision: bigintToNumber(user.vault_revision),
      purgedThroughRevision: bigintToNumber(user.purged_through_revision),
      fullResync,
      items: items.map((item) => this.toItemDto(item)),
    };
  }

  async pushChanges(
    userId: string,
    sessionId: string,
    dto: PushVaultChangesDto,
    client: ClientInfoData,
  ): Promise<VaultPushResponseDto> {
    const changes = dto.items.map((item) => ({
      ...item,
      id: item.id.toLowerCase(),
    }));
    const ids = changes.map((c) => c.id);
    if (new Set(ids).size !== ids.length) {
      throw new BadRequestException(
        'Un mismo elemento no puede aparecer más de una vez en el lote.',
      );
    }

    try {
      return await this.applyChanges(userId, sessionId, changes, client);
    } catch (error) {
      if (error instanceof ConflictException) {
        await this.auditService.recordSafely({
          userId,
          sessionId,
          event: AuditEvent.VaultSyncConflict,
          outcome: 'failure',
          metadata: {
            items: changes.length,
            conflicts: this.conflictCount(error),
          },
          client,
        });
      }
      throw error;
    }
  }

  private applyChanges(
    userId: string,
    sessionId: string,
    changes: VaultChange[],
    client: ClientInfoData,
  ): Promise<VaultPushResponseDto> {
    return this.prisma.$transaction(async (tx) => {
      // El UPDATE bloquea la fila del usuario y serializa lotes concurrentes
      const user = await tx.users.update({
        where: { id: userId },
        data: { vault_revision: { increment: 1 } },
        select: { vault_revision: true, deleted_at: true },
      });
      if (user.deleted_at) {
        throw new NotFoundException('Usuario no encontrado.');
      }
      const revision = user.vault_revision;

      const existing = await tx.vault_items.findMany({
        where: { id: { in: changes.map((c) => c.id) } },
        select: { id: true, user_id: true, version: true },
      });
      const byId = new Map(existing.map((e) => [e.id, e]));

      const conflicts: VaultConflictDto[] = [];
      for (const change of changes) {
        const current = byId.get(change.id);
        if (!current) {
          if (change.baseVersion !== 0 || change.deleted) {
            conflicts.push({
              id: change.id,
              reason: 'not_found',
              currentVersion: null,
            });
          }
        } else if (current.user_id !== userId) {
          conflicts.push({
            id: change.id,
            reason: 'id_unavailable',
            currentVersion: null,
          });
        } else if (current.version !== change.baseVersion) {
          conflicts.push({
            id: change.id,
            reason: 'version_mismatch',
            currentVersion: current.version,
          });
        }
      }

      if (conflicts.length > 0) {
        // Lanzar dentro de la transacción revierte también el incremento de revisión
        throw new ConflictException({
          error: 'VaultSyncConflict',
          message:
            'Conflicto de sincronización: descarga los cambios pendientes y vuelve a intentarlo.',
          details: { conflicts },
        });
      }

      const now = new Date();
      const applied: VaultPushResponseDto['applied'] = [];

      for (const change of changes) {
        const version = change.baseVersion + 1;

        if (change.deleted) {
          await tx.vault_items.update({
            where: { id: change.id },
            data: {
              version,
              revision,
              deleted_at: now,
              nonce: new Uint8Array(0),
              ciphertext: new Uint8Array(0),
            },
          });
        } else {
          const payload = {
            version,
            revision,
            deleted_at: null,
            nonce: fromBase64(change.nonce!),
            ciphertext: fromBase64(change.ciphertext!),
            format_version: change.formatVersion!,
          };
          if (byId.has(change.id)) {
            await tx.vault_items.update({
              where: { id: change.id },
              data: payload,
            });
          } else {
            await tx.vault_items.create({
              data: { id: change.id, user_id: userId, ...payload },
            });
          }
        }

        applied.push({
          id: change.id,
          version,
          revision: bigintToNumber(revision),
        });
      }

      const deleted = changes.filter((c) => c.deleted).length;
      const created = changes.filter(
        (c) => !c.deleted && !byId.has(c.id),
      ).length;
      await this.auditService.record(
        {
          userId,
          sessionId,
          event: AuditEvent.VaultSyncPush,
          outcome: 'success',
          metadata: {
            revision: bigintToNumber(revision),
            created,
            updated: changes.length - created - deleted,
            deleted,
          },
          client,
        },
        tx,
      );

      return { revision: bigintToNumber(revision), applied };
    });
  }

  private conflictCount(error: ConflictException): number {
    const body = error.getResponse() as {
      details?: { conflicts?: unknown[] };
    };
    return body.details?.conflicts?.length ?? 0;
  }

  private toItemDto(item: vault_items): VaultItemDto {
    const deleted = item.deleted_at !== null;
    return {
      id: item.id,
      version: item.version,
      revision: bigintToNumber(item.revision),
      deleted,
      ...(deleted
        ? {}
        : {
            nonce: toBase64(item.nonce),
            ciphertext: toBase64(item.ciphertext),
          }),
      formatVersion: item.format_version,
      updatedAt: item.updated_at,
    };
  }
}
