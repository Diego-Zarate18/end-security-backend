import { UserResponseDto } from '../../users/dto';

export class AuthResponseDto {
  accessToken?: string;
  user?: UserResponseDto;
  requires2FA?: boolean;
  tempToken?: string;
}

