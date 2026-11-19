export class SessionDto {
  id: string;
  deviceName: string;
  createdAt: Date;
  lastUsedAt: Date | null;
  expiresAt: Date;
  /** true para la sesión con la que se hizo la petición. */
  current: boolean;
}

export class RevokedSessionsDto {
  revoked: number;
}
