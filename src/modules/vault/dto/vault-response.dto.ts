export class VaultItemDto {
  id: string;
  version: number;
  revision: number;
  deleted: boolean;
  /** Ausentes en tombstones (elementos borrados). */
  nonce?: string;
  ciphertext?: string;
  formatVersion: number;
  updatedAt: Date;
}

export class VaultSyncResponseDto {
  /** Revisión actual de la bóveda; el cliente la guarda como cursor. */
  revision: number;
  purgedThroughRevision: number;
  /** true: el cliente debe reemplazar su copia local por `items`. */
  fullResync: boolean;
  items: VaultItemDto[];
}

export class VaultConflictDto {
  id: string;
  reason: 'version_mismatch' | 'not_found' | 'id_unavailable';
  currentVersion: number | null;
}

export class VaultPushResponseDto {
  revision: number;
  applied: { id: string; version: number; revision: number }[];
}
