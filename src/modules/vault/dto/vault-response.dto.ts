export class VaultResponseDto {
  id: string;
  userId: string;
  encryptedBlob: string;
  salt: string;
  iv: string;
  version: number;
  updatedAt: Date;
}

