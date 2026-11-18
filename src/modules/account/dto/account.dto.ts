import { Transform, Type } from 'class-transformer';
import {
  IsDefined,
  IsInt,
  IsOptional,
  Matches,
  Min,
  ValidateNested,
} from 'class-validator';
import { IsBase64Bytes } from '../../../common/validators';
import { KdfParamsDto, ProtectedVaultKeyDto } from '../../auth/dto';

/** 6 dígitos (TOTP) o un código de recuperación "k7m2q-x9rtb". */
const SECOND_FACTOR = /^(\d{6}|[a-hj-km-np-z2-9]{5}-?[a-hj-km-np-z2-9]{5})$/i;
const emptyToUndefined = ({ value }: { value: unknown }) =>
  value === '' || value === null ? undefined : value;

class SecondFactorDto {
  /** Obligatorio solo si la cuenta tiene 2FA activo. */
  @Transform(emptyToUndefined)
  @IsOptional()
  @Matches(SECOND_FACTOR, {
    message:
      'code debe ser un código de 6 dígitos o un código de recuperación.',
  })
  code?: string;
}

export class DeleteAccountDto extends SecondFactorDto {
  @IsBase64Bytes(32, 64)
  authHash: string;
}

/**
 * La app deriva claves nuevas de la nueva contraseña maestra: auth key, salt y
 * parámetros KDF nuevos, y la MISMA clave de bóveda cifrada con la nueva
 * master key (pvk). Los elementos de la bóveda no cambian.
 */
export class ChangeMasterPasswordDto extends SecondFactorDto {
  @IsBase64Bytes(32, 64)
  currentAuthHash: string;

  @IsBase64Bytes(32, 64)
  newAuthHash: string;

  @IsDefined()
  @ValidateNested()
  @Type(() => KdfParamsDto)
  kdf: KdfParamsDto;

  @IsDefined()
  @ValidateNested()
  @Type(() => ProtectedVaultKeyDto)
  pvk: ProtectedVaultKeyDto;

  /** key_version con la que la app envolvió la pvk; si otro teléfono cambió antes, 409. */
  @IsOptional()
  @IsInt()
  @Min(1)
  expectedKeyVersion?: number;
}

export class PasswordChangedDto {
  keyVersion: number;
  otherSessionsRevoked: number;
}
