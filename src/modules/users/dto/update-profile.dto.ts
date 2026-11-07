import { Transform } from 'class-transformer';
import { IsNotEmpty, IsString, MaxLength } from 'class-validator';
import { trimString } from '../../auth/dto/normalize';

export class UpdateProfileDto {
  @Transform(trimString)
  @IsString()
  @IsNotEmpty({ message: 'El nombre para mostrar es requerido.' })
  @MaxLength(64)
  displayName: string;
}
