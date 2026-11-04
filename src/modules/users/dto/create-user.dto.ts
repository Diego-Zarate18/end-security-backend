/**
 * Datos internos para crear un usuario. No es un DTO de entrada HTTP: la
 * validación ocurre en RegisterDto y aquí ya llega el material decodificado.
 */
export interface CreateUserData {
  email: string;
  displayName: string;
  /** Hash Argon2id (formato PHC) calculado por el servidor. */
  authHash: string;
  kdfSalt: Uint8Array<ArrayBuffer>;
  kdfMemoryKib: number;
  kdfIterations: number;
  kdfParallelism: number;
  pvkCiphertext: Uint8Array<ArrayBuffer>;
  pvkNonce: Uint8Array<ArrayBuffer>;
}
