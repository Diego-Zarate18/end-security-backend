import { Transform, Type } from 'class-transformer';
import {
  IsDefined,
  IsEmail,
  IsInt,
  IsNotEmpty,
  IsString,
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

  // Mínimos OWASP para Argon2id: 19 MiB, 2 iteraciones, 1 hilo
  @IsInt()
  @Min(19456)
  @Max(1048576)
  memoryKib: number;

  @IsInt()
  @Min(2)
  @Max(10)
  iterations: number;

  @IsInt()
  @Min(1)
  @Max(16)
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
  @Transform(normalizeEmail)
  @IsEmail({}, { message: 'El correo electrónico no es válido.' })
  @MaxLength(254)
  email: string;

  @Transform(trimString)
  @IsString()
  @IsNotEmpty({ message: 'El nombre para mostrar es requerido.' })
  @MaxLength(64)
  displayName: string;

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
