export class UserResponseDto {
  id: string;
  email: string;
  displayName: string;
  marketingOptIn: boolean;
  emailVerified: boolean;
  twoFactorEnabled: boolean;
  createdAt: Date;
}
