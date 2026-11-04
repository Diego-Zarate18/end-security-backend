import { IsString, Matches, MaxLength } from 'class-validator';

export class RefreshTokenDto {
  @IsString()
  @MaxLength(128)
  @Matches(/^[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/, {
    message: 'El refresh token no tiene un formato válido.',
  })
  refreshToken: string;
}
