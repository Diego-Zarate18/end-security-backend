export class UserResponseDto {
  id: string;
  email: string;
  displayName: string;
  emailVerified: boolean;
  twoFactorEnabled: boolean;
  createdAt: Date;
}
