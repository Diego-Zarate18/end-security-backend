export class AuditLogItemDto {
  id: number;
  eventType: string;
  outcome: string;
  occurredAt: Date;
  metadata: unknown;
  deviceName: string | null;
  ip: string | null;
  userAgent: string | null;
}

export class AuditLogPageDto {
  items: AuditLogItemDto[];
  /** Pasar como `before` para la siguiente página; null si no hay más. */
  nextCursor: number | null;
}

export class AuditChainReportDto {
  valid: boolean;
  checkedEntries: number;
  firstInvalidId?: number;
  reason?: 'broken_link' | 'hash_mismatch';
}
