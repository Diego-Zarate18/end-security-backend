export class CodeSentDto {
  /** Destino enmascarado, p. ej. "di***@endsecurity.com". */
  sentTo: string;
  /** false si ya se envió uno hace menos de 60 s; sigue valiendo el anterior. */
  codeSent: boolean;
  expiresAt: Date;
  resendAvailableInSeconds: number;
}
