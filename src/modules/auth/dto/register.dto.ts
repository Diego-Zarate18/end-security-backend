import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class RegisterDto {
  @IsEmail({}, { message: 'El correo electrónico no es válido.' })
  @IsNotEmpty({ message: 'El correo electrónico es requerido.' })
  email: string;

  @IsString({ message: 'El hash de contraseña debe ser una cadena de texto.' })
  @IsNotEmpty({ message: 'El hash de contraseña es requerido.' })
  @MinLength(16, {
    message: 'El hash de contraseña no cumple con la longitud mínima de seguridad.',
  })
  passwordHash: string;
}

