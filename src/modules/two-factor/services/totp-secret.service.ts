import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { parseTotpKeys } from '../../../config/totp-keys';

export interface EncryptedSecret {
  ciphertext: Uint8Array<ArrayBuffer>;
  nonce: Uint8Array<ArrayBuffer>;
  keyId: number;
}

const toBytes = (buffer: Buffer): Uint8Array<ArrayBuffer> => {
  const out = new Uint8Array(buffer.length);
  out.set(buffer);
  return out;
};

/**
 * Cifra el secreto TOTP con AES-256-GCM antes de guardarlo. A diferencia de la
 * bóveda, el servidor sí necesita leerlo para validar los códigos, así que la
 * clave vive en el servidor (TOTP_ENCRYPTION_KEYS) y no en la base de datos.
 * `server_key_id` permite rotar la clave sin perder los secretos viejos.
 */
@Injectable()
export class TotpSecretService {
  private readonly keys: Map<number, Buffer>;
  private readonly currentKeyId: number;

  constructor(configService: ConfigService) {
    const parsed = parseTotpKeys(
      configService.getOrThrow<string>('TOTP_ENCRYPTION_KEYS'),
    );
    this.keys = parsed.keys;
    this.currentKeyId = parsed.currentKeyId;
  }

  encrypt(secret: string, userId: string): EncryptedSecret {
    const nonce = randomBytes(12);
    const cipher = createCipheriv(
      'aes-256-gcm',
      this.key(this.currentKeyId),
      nonce,
    );
    // El user_id como AAD: un secreto copiado a otra fila no descifra
    cipher.setAAD(Buffer.from(userId, 'utf8'));
    const ciphertext = Buffer.concat([
      cipher.update(secret, 'utf8'),
      cipher.final(),
      cipher.getAuthTag(),
    ]);
    return {
      ciphertext: toBytes(ciphertext),
      nonce: toBytes(nonce),
      keyId: this.currentKeyId,
    };
  }

  decrypt(
    data: { ciphertext: Uint8Array; nonce: Uint8Array; keyId: number },
    userId: string,
  ): string {
    const body = Buffer.from(data.ciphertext);
    const decipher = createDecipheriv(
      'aes-256-gcm',
      this.key(data.keyId),
      Buffer.from(data.nonce),
    );
    decipher.setAAD(Buffer.from(userId, 'utf8'));
    decipher.setAuthTag(body.subarray(body.length - 16));
    return Buffer.concat([
      decipher.update(body.subarray(0, body.length - 16)),
      decipher.final(),
    ]).toString('utf8');
  }

  private key(id: number): Buffer {
    const key = this.keys.get(id);
    if (!key) {
      throw new Error(`No existe la clave TOTP con id ${id}.`);
    }
    return key;
  }
}
