import { Transform } from 'class-transformer';
import { IsEmail, IsNotEmpty, IsString, MaxLength } from 'class-validator';
import { IsBase64Bytes } from '../../../common/validators';
import { normalizeEmail, trimString } from './normalize';

export class LoginDto {
  @Transform(normalizeEmail)
  @IsEmail({}, { message: 'El correo electrónico no es válido.' })
  @MaxLength(254)
  email: string;

  @IsBase64Bytes(32, 64)
  authHash: string;

  @Transform(trimString)
  @IsString()
  @IsNotEmpty({ message: 'El nombre del dispositivo es requerido.' })
  @MaxLength(64)
  deviceName: string;
}
