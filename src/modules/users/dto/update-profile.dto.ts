import { Transform } from 'class-transformer';
import {
  IsBoolean,
  IsNotEmpty,
  IsOptional,
  IsString,
  MaxLength,
} from 'class-validator';
import { trimString } from '../../auth/dto/normalize';

/** Al menos uno de los dos campos (se comprueba en UsersService). */
export class UpdateProfileDto {
  @Transform(trimString)
  @IsOptional()
  @IsString()
  @IsNotEmpty({ message: 'El nombre para mostrar es requerido.' })
  @MaxLength(64)
  displayName?: string;

  /** Aceptar o retirar las finalidades secundarias (DEC-64). */
  @IsOptional()
  @IsBoolean()
  marketingOptIn?: boolean;
}
