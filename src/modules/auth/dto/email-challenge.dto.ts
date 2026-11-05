import { IsJWT, Matches } from 'class-validator';

export class ResendEmailCodeDto {
  @IsJWT({ message: 'challengeToken no es válido.' })
  challengeToken: string;
}

export class VerifyEmailDto extends ResendEmailCodeDto {
  @Matches(/^\d{6}$/, { message: 'El código debe tener 6 dígitos.' })
  code: string;
}
