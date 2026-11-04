import { Type } from 'class-transformer';
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsBoolean,
  IsInt,
  IsOptional,
  IsUUID,
  Max,
  Min,
  ValidateIf,
  ValidateNested,
} from 'class-validator';
import { IsBase64Bytes } from '../../../common/validators';

export const VAULT_PUSH_MAX_ITEMS = 50;
export const VAULT_ITEM_MAX_CIPHERTEXT_BYTES = 32 * 1024;

/** GET /vault/sync?since=<revisión> */
export class SyncQueryDto {
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  since?: number;
}

/** Un cambio sobre un elemento de la bóveda (alta, edición o borrado). */
export class VaultItemChangeDto {
  /** UUID generado por el cliente. */
  @IsUUID('all')
  id: string;

  /** Versión que el cliente modificó; 0 para un elemento nuevo. */
  @IsInt()
  @Min(0)
  baseVersion: number;

  @IsOptional()
  @IsBoolean()
  deleted?: boolean;

  @ValidateIf((o: VaultItemChangeDto) => !o.deleted)
  @IsBase64Bytes(12, 24)
  nonce?: string;

  // Mínimo 17 bytes: al menos 1 byte de datos + 16 del tag de AES-GCM
  @ValidateIf((o: VaultItemChangeDto) => !o.deleted)
  @IsBase64Bytes(17, VAULT_ITEM_MAX_CIPHERTEXT_BYTES)
  ciphertext?: string;

  @ValidateIf((o: VaultItemChangeDto) => !o.deleted)
  @IsInt()
  @Min(1)
  @Max(32767)
  formatVersion?: number;
}

/** POST /vault/sync */
export class PushVaultChangesDto {
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(VAULT_PUSH_MAX_ITEMS)
  @ValidateNested({ each: true })
  @Type(() => VaultItemChangeDto)
  items: VaultItemChangeDto[];
}
