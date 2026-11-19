import { Transform, Type } from 'class-transformer';
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsBoolean,
  IsDefined,
  IsInt,
  IsOptional,
  IsUUID,
  Matches,
  Max,
  Min,
  ValidateIf,
  ValidateNested,
} from 'class-validator';
import { IsBase64Bytes } from '../../../common/validators';
import { ProtectedVaultKeyDto } from '../../auth/dto';

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

export const VAULT_ROTATION_MAX_ITEMS = 5000;

/** Un elemento recifrado con la nueva clave de la bóveda. */
export class RotatedItemDto {
  @IsUUID('all')
  id: string;

  @IsBase64Bytes(12, 24)
  nonce: string;

  @IsBase64Bytes(17, VAULT_ITEM_MAX_CIPHERTEXT_BYTES)
  ciphertext: string;

  @IsInt()
  @Min(1)
  @Max(32767)
  formatVersion: number;
}

/**
 * POST /vault/rotate-key. La app genera una clave de bóveda nueva, recifra con
 * ella TODOS los elementos vigentes y cifra la clave nueva con su master key
 * (pvk). El servidor aplica todo o nada.
 */
export class RotateVaultKeyDto {
  @IsBase64Bytes(32, 64)
  authHash: string;

  @Transform(({ value }: { value: unknown }) =>
    value === '' || value === null ? undefined : value,
  )
  @IsOptional()
  @Matches(/^(\d{6}|[a-hj-km-np-z2-9]{5}-?[a-hj-km-np-z2-9]{5})$/i, {
    message:
      'code debe ser un código de 6 dígitos o un código de recuperación.',
  })
  code?: string;

  /** key_version que la app tenía al recifrar; si cambió, responde 409. */
  @IsInt()
  @Min(1)
  keyVersion: number;

  @IsDefined()
  @ValidateNested()
  @Type(() => ProtectedVaultKeyDto)
  pvk: ProtectedVaultKeyDto;

  @IsArray()
  @ArrayMaxSize(VAULT_ROTATION_MAX_ITEMS)
  @ValidateNested({ each: true })
  @Type(() => RotatedItemDto)
  items: RotatedItemDto[];
}
