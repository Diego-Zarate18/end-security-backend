import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Prisma } from '@prisma/client';
import { timingSafeEqual } from 'crypto';
import { isIP } from 'net';
import type { ClientInfoData } from '../../../common/decorators';
import { bigintToNumber } from '../../../common/utils';
import { PrismaService } from '../../../database/prisma.service';
import { AuditEvent, AuditOutcome } from '../audit.constants';
import { AuditChainReportDto, AuditLogItemDto, AuditLogPageDto } from '../dto';
import { computeAuditHash } from './audit-chain';

export interface AuditRecordInput {
  userId: string;
  sessionId?: string | null;
  event: AuditEvent;
  outcome: AuditOutcome;
  /** Nunca incluir authHash, tokens, ciphertext ni correos de terceros. */
  metadata?: Record<string, string | number | boolean | null>;
  client?: ClientInfoData;
}

const VERIFY_BATCH = 500;
const MAX_USER_AGENT = 512;

/**
 * Bitácora de seguridad a prueba de manipulación: cada fila guarda el HMAC de
 * la anterior del mismo usuario (`prev_hash`) y el suyo (`hash`).
 */
@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);
  private readonly key: Buffer;

  constructor(
    private readonly prisma: PrismaService,
    configService: ConfigService,
  ) {
    this.key = Buffer.from(
      configService.getOrThrow<string>('AUDIT_HMAC_KEY'),
      'utf8',
    );
  }

  /**
   * Registra un evento. Con `tx`, queda dentro de la transacción del negocio
   * (si ésta se revierte, el evento también); sin `tx`, abre la suya.
   */
  async record(
    input: AuditRecordInput,
    tx?: Prisma.TransactionClient,
  ): Promise<void> {
    if (tx) {
      await this.append(tx, input);
      return;
    }
    await this.prisma.$transaction((t) => this.append(t, input));
  }

  /**
   * Para eventos de fallo que se registran justo antes de lanzar un error: un
   * problema al auditar se reporta en el log, pero no oculta el error original.
   */
  async recordSafely(input: AuditRecordInput): Promise<void> {
    try {
      await this.record(input);
    } catch (error) {
      this.logger.error(
        `[AuditWriteFailed] ${input.event}/${input.outcome}`,
        error instanceof Error ? error.stack : undefined,
      );
    }
  }

  async list(
    userId: string,
    limit: number,
    before?: number,
  ): Promise<AuditLogPageDto> {
    const rows = await this.prisma.audit_log.findMany({
      where: {
        user_id: userId,
        ...(before !== undefined ? { id: { lt: BigInt(before) } } : {}),
      },
      orderBy: { id: 'desc' },
      take: limit + 1,
      include: {
        pii: true,
        session: { select: { device_name: true } },
      },
    });

    const page = rows.slice(0, limit);
    const items: AuditLogItemDto[] = page.map((row) => ({
      id: bigintToNumber(row.id),
      eventType: row.event_type,
      outcome: row.outcome,
      occurredAt: row.occurred_at,
      metadata: row.metadata,
      deviceName: row.session?.device_name ?? null,
      ip: row.pii?.ip ?? null,
      userAgent: row.pii?.user_agent ?? null,
    }));

    return {
      items,
      nextCursor:
        rows.length > limit ? bigintToNumber(page[page.length - 1].id) : null,
    };
  }

  /** Recorre la cadena completa del usuario y señala el primer eslabón alterado. */
  async verify(userId: string): Promise<AuditChainReportDto> {
    let prevHash: Uint8Array | null = null;
    let lastId: bigint | undefined;
    let checked = 0;

    for (;;) {
      const batch = await this.prisma.audit_log.findMany({
        where: {
          user_id: userId,
          ...(lastId !== undefined ? { id: { gt: lastId } } : {}),
        },
        orderBy: { id: 'asc' },
        take: VERIFY_BATCH,
      });
      if (batch.length === 0) break;

      for (const row of batch) {
        const linked =
          prevHash === null
            ? row.prev_hash === null
            : row.prev_hash !== null && this.equal(row.prev_hash, prevHash);
        if (!linked) {
          return this.broken(checked, row.id, 'broken_link');
        }

        const expected = computeAuditHash(this.key, {
          id: row.id,
          prevHash: row.prev_hash,
          userId: row.user_id,
          eventType: row.event_type,
          outcome: row.outcome,
          occurredAt: row.occurred_at,
          metadata: row.metadata,
        });
        if (!this.equal(expected, row.hash)) {
          return this.broken(checked, row.id, 'hash_mismatch');
        }

        prevHash = row.hash;
        lastId = row.id;
        checked++;
      }
    }

    return { valid: true, checkedEntries: checked };
  }

  private async append(
    tx: Prisma.TransactionClient,
    input: AuditRecordInput,
  ): Promise<void> {
    // Serializa las escrituras de un mismo usuario para que la cadena no se bifurque
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${input.userId}::text, 0))`;

    const previous = await tx.audit_log.findFirst({
      where: { user_id: input.userId },
      orderBy: { id: 'desc' },
      select: { hash: true },
    });

    // El id entra al HMAC, así que se reserva antes de insertar
    const [{ id }] = await tx.$queryRaw<{ id: bigint }[]>`
      SELECT nextval(pg_get_serial_sequence('audit_log', 'id')) AS id`;

    const occurredAt = new Date();
    // Ida y vuelta por JSON: lo que se hashea es exactamente lo que guarda JSONB
    const metadata = JSON.parse(
      JSON.stringify(input.metadata ?? {}),
    ) as Prisma.InputJsonObject;
    const prevHash = previous?.hash ?? null;

    await tx.audit_log.create({
      data: {
        id,
        user_id: input.userId,
        session_id: input.sessionId ?? null,
        event_type: input.event,
        outcome: input.outcome,
        occurred_at: occurredAt,
        metadata,
        prev_hash: prevHash,
        hash: computeAuditHash(this.key, {
          id,
          prevHash,
          userId: input.userId,
          eventType: input.event,
          outcome: input.outcome,
          occurredAt,
          metadata,
        }),
      },
    });

    const ip = input.client?.ipAddress;
    if (input.client && ip && isIP(ip)) {
      await tx.audit_log_pii.create({
        data: {
          id,
          ip,
          user_agent: input.client.userAgent.slice(0, MAX_USER_AGENT),
        },
      });
    }
  }

  private equal(a: Uint8Array, b: Uint8Array): boolean {
    return a.length === b.length && timingSafeEqual(a, b);
  }

  private broken(
    checked: number,
    id: bigint,
    reason: AuditChainReportDto['reason'],
  ): AuditChainReportDto {
    return {
      valid: false,
      checkedEntries: checked,
      firstInvalidId: bigintToNumber(id),
      reason,
    };
  }
}
