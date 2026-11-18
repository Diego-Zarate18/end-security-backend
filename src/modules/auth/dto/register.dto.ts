import { Transform, Type } from 'class-transformer';
import {
  IsDefined,
  IsEmail,
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  IsUUID,
  Max,
  MaxLength,
  Min,
  ValidateNested,
} from 'class-validator';
import { IsBase64Bytes } from '../../../common/validators';
import { normalizeEmail, trimString } from './normalize';

/** Parámetros Argon2id usados por el cliente para derivar la master key. */
export class KdfParamsDto {
  @IsBase64Bytes(16, 64)
  salt: string;

  // Piso de DEC-05: 64 MiB, 3 iteraciones, 1 hilo (la app no usa más hilos)
  @IsInt()
  @Min(65536)
  @Max(1048576)
  memoryKib: number;

  @IsInt()
  @Min(3)
  @Max(10)
  iterations: number;

  @IsInt()
  @Min(1)
  @Max(1)
  parallelism: number;
}

/** Protected Vault Key: clave de la bóveda cifrada con la master key (AES-GCM). */
export class ProtectedVaultKeyDto {
  @IsBase64Bytes(32, 128)
  ciphertext: string;

  @IsBase64Bytes(12, 24)
  nonce: string;
}

export class RegisterDto {
  /** Lo genera la app: forma parte de la AAD de la pvk y de cada elemento (DEC-05). */
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.toLowerCase() : value,
  )
  @IsUUID()
  userId: string;

  @Transform(normalizeEmail)
  @IsEmail({}, { message: 'El correo electrónico no es válido.' })
  @MaxLength(254)
  email: string;

  /** Opcional: la app no lo pide al registrarse. */
  @Transform(trimString)
  @IsOptional()
  @IsString()
  @MaxLength(64)
  displayName?: string;

  /** Auth key derivado en el cliente (nunca la contraseña maestra). */
  @IsBase64Bytes(32, 64)
  authHash: string;

  @IsDefined()
  @ValidateNested()
  @Type(() => KdfParamsDto)
  kdf: KdfParamsDto;

  @IsDefined()
  @ValidateNested()
  @Type(() => ProtectedVaultKeyDto)
  pvk: ProtectedVaultKeyDto;

  @Transform(trimString)
  @IsString()
  @IsNotEmpty({ message: 'El nombre del dispositivo es requerido.' })
  @MaxLength(64)
  deviceName: string;
}
