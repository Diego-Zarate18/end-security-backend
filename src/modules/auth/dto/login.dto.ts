import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class LoginDto {
  @IsEmail({}, { message: 'El correo electrónico no es válido.' })
  @IsNotEmpty({ message: 'El correo electrónico es requerido.' })
  email: string;

  @IsString({ message: 'El hash de contraseña debe ser una cadena de texto.' })
  @IsNotEmpty({ message: 'El hash de contraseña es requerido.' })
  passwordHash: string;
}

