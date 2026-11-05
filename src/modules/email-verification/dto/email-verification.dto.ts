import { Transform } from 'class-transformer';
import { IsEmail, Matches, MaxLength } from 'class-validator';
import { IsBase64Bytes } from '../../../common/validators';
import { normalizeEmail } from '../../auth/dto/normalize';

export class ConfirmEmailCodeDto {
  @Matches(/^\d{6}$/, { message: 'El código debe tener 6 dígitos.' })
  code: string;
}

export class RequestEmailChangeDto {
  @Transform(normalizeEmail)
  @IsEmail({}, { message: 'El correo electrónico no es válido.' })
  @MaxLength(254)
  newEmail: string;

  /** Reautenticación: auth key derivado de la contraseña maestra actual. */
  @IsBase64Bytes(32, 64)
  authHash: string;
}

export class CodeSentDto {
  /** Destino enmascarado, p. ej. "di***@endsecurity.com". */
  sentTo: string;
  expiresAt: Date;
  resendAvailableInSeconds: number;
}
