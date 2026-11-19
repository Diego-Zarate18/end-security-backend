import { IsJWT, IsOptional, Matches } from 'class-validator';
import { IsBase64Bytes } from '../../../common/validators';

const TOTP = /^\d{6}$/;
/** 10 caracteres sin ambiguos (sin 0/o, 1/l/i), con guion opcional: "k7m2q-x9rtb". */
const RECOVERY = /^[a-hj-km-np-z2-9]{5}-?[a-hj-km-np-z2-9]{5}$/i;
const TOTP_OR_RECOVERY =
  /^(\d{6}|[a-hj-km-np-z2-9]{5}-?[a-hj-km-np-z2-9]{5})$/i;

/** Reautenticación con la contraseña maestra (auth key derivado). */
export class ReauthDto {
  @IsBase64Bytes(32, 64)
  authHash: string;
}

export class ActivateTwoFactorDto {
  @Matches(TOTP, { message: 'El código debe tener 6 dígitos.' })
  code: string;
}

/** Segundo paso del login: código TOTP o, si se perdió el teléfono, un código de recuperación. */
export class VerifyTwoFactorDto {
  @IsJWT({ message: 'challengeToken no es válido.' })
  challengeToken: string;

  @IsOptional()
  @Matches(TOTP, { message: 'El código debe tener 6 dígitos.' })
  code?: string;

  @IsOptional()
  @Matches(RECOVERY, { message: 'El código de recuperación no es válido.' })
  recoveryCode?: string;
}

/** Desactivar o regenerar códigos: contraseña maestra + segundo factor. */
export class SensitiveTwoFactorDto extends ReauthDto {
  @Matches(TOTP_OR_RECOVERY, {
    message: 'Envía un código de 6 dígitos o un código de recuperación.',
  })
  code: string;
}

export class TwoFactorStatusDto {
  status: 'disabled' | 'pending' | 'active';
  activatedAt: Date | null;
  recoveryCodesRemaining: number;
}

export class TwoFactorSetupDto {
  /** Para escribirlo a mano en la app autenticadora. */
  secret: string;
  otpauthUrl: string;
  /** PNG en data URL; ábrelo en el navegador para escanearlo. */
  qrCodeDataUrl: string;
}

export class RecoveryCodesDto {
  /** Se muestran una sola vez. */
  recoveryCodes: string[];
}
