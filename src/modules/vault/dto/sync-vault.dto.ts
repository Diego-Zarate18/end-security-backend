import { IsInt, IsNotEmpty, IsString, Min } from 'class-validator';

export class SyncVaultDto {
  @IsString({ message: 'El blob cifrado debe ser una cadena de texto.' })
  @IsNotEmpty({ message: 'El contenido cifrado (encryptedBlob) es requerido.' })
  encryptedBlob: string;

  @IsString({ message: 'El salt debe ser una cadena de texto.' })
  @IsNotEmpty({ message: 'El salt criptográfico es requerido.' })
  salt: string;

  @IsString({ message: 'El vector de inicialización (IV) debe ser una cadena de texto.' })
  @IsNotEmpty({ message: 'El vector de inicialización (IV) es requerido.' })
  iv: string;

  @IsInt({ message: 'La versión de la bóveda debe ser un número entero.' })
  @Min(1, { message: 'La versión de la bóveda debe ser mayor o igual a 1.' })
  version: number;
}

