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
import { ReauthService } from '../../account/services';
import { SessionsService } from '../../auth/services';
import { UsersService } from '../../users/services';
import {
  PushVaultChangesDto,
  RotateVaultKeyDto,
  VaultKeyRotatedDto,
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
    private readonly usersService: UsersService,
    private readonly sessionsService: SessionsService,
    private readonly reauth: ReauthService,
  ) {}

  async getChanges(
    userId: string,
    since: number,
  ): Promise<VaultSyncResponseDto> {
    const user = await this.prisma.users.findFirst({
      where: { id: userId, deleted_at: null },
      select: {
        vault_revision: true,
        purged_through_revision: true,
        key_version: true,
      },
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
      keyVersion: user.key_version,
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

  /**
   * Cambia la clave de la bóveda: recibe todos los elementos vigentes recifrados
   * y la nueva clave protegida (pvk). Es todo o nada: si falta o sobra algún
   * elemento, o si otro dispositivo cambió las llaves, no se aplica nada (409).
   * Cierra los demás dispositivos, que tenían la clave anterior.
   */
  async rotateKey(
    actor: { userId: string; sessionId: string; client: ClientInfoData },
    dto: RotateVaultKeyDto,
  ): Promise<VaultKeyRotatedDto> {
    const event = AuditEvent.VaultKeyRotation;
    const user = await this.usersService.findActiveById(actor.userId);
    await this.reauth.verify(actor, user, dto.authHash, dto.code, event);

    const items = dto.items.map((item) => ({
      ...item,
      id: item.id.toLowerCase(),
    }));
    const ids = new Set(items.map((i) => i.id));
    if (ids.size !== items.length) {
      throw new BadRequestException(
        'Un mismo elemento no puede aparecer más de una vez.',
      );
    }

    return this.prisma.$transaction(
      async (tx) => {
        // El UPDATE bloquea la fila del usuario: ninguna sincronización se cuela en medio
        const locked = await tx.users.update({
          where: { id: actor.userId },
          data: { vault_revision: { increment: 1 } },
          select: { vault_revision: true, key_version: true },
        });
        if (locked.key_version !== dto.keyVersion) {
          throw new ConflictException({
            error: 'KeyVersionMismatch',
            message:
              'Las llaves de la cuenta cambiaron en otro dispositivo. Inicia sesión de nuevo y repite la rotación.',
            details: { currentKeyVersion: locked.key_version },
          });
        }

        const current = await tx.vault_items.findMany({
          where: { user_id: actor.userId, deleted_at: null },
          select: { id: true },
        });
        const currentIds = new Set(current.map((c) => c.id));
        const missing = [...currentIds].filter((id) => !ids.has(id));
        const unknown = [...ids].filter((id) => !currentIds.has(id));
        if (missing.length > 0 || unknown.length > 0) {
          throw new ConflictException({
            error: 'VaultChanged',
            message:
              'La bóveda cambió: descarga los cambios, recifra todos los elementos y vuelve a intentarlo.',
            details: { missing, unknown },
          });
        }

        const revision = locked.vault_revision;
        for (const item of items) {
          await tx.vault_items.update({
            where: { id: item.id },
            data: {
              nonce: fromBase64(item.nonce),
              ciphertext: fromBase64(item.ciphertext),
              format_version: item.formatVersion,
              version: { increment: 1 },
              revision,
            },
          });
        }

        const updated = await tx.users.update({
          where: { id: actor.userId },
          data: {
            pvk_ciphertext: fromBase64(dto.pvk.ciphertext),
            pvk_nonce: fromBase64(dto.pvk.nonce),
            key_version: { increment: 1 },
          },
          select: { key_version: true },
        });

        const otherSessionsRevoked = await this.sessionsService.revokeOthers(
          actor.userId,
          actor.sessionId,
          'key_rotation',
          tx,
        );

        await this.auditService.record(
          {
            userId: actor.userId,
            sessionId: actor.sessionId,
            event,
            outcome: 'success',
            metadata: {
              keyVersion: updated.key_version,
              itemsRotated: items.length,
              otherSessionsRevoked,
            },
            client: actor.client,
          },
          tx,
        );

        return {
          keyVersion: updated.key_version,
          revision: bigintToNumber(revision),
          itemsRotated: items.length,
          otherSessionsRevoked,
        };
      },
      // Con miles de elementos la transacción tarda más que los 5 s por defecto
      { timeout: 60_000 },
    );
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
