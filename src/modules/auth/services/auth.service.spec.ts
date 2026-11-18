import { UnauthorizedException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import * as argon2 from 'argon2';
import { AuthService } from './auth.service';

const b64 = (bytes: number) => Buffer.alloc(bytes, 7).toString('base64');
const client = { ipAddress: '203.0.113.9', userAgent: 'jest' };

const registerDto = {
  userId: '3f2504e0-4f89-41d3-9a0c-0305e82c3301',
  email: 'ana@example.com',
  authHash: b64(32),
  kdf: { salt: b64(16), memoryKib: 65536, iterations: 3, parallelism: 1 },
  pvk: { ciphertext: b64(48), nonce: b64(12) },
  deviceName: 'Pixel',
};

function build() {
  const prisma = {
    $transaction: jest.fn((cb: (tx: unknown) => unknown) => cb({})),
    audit_log: { count: jest.fn().mockResolvedValue(0) },
  };
  const usersService = {
    findByEmail: jest.fn().mockResolvedValue(null),
    findActiveByEmail: jest.fn(),
    create: jest.fn(),
  };
  const tokenService = {
    signEmailVerificationChallenge: jest.fn().mockReturnValue('challenge'),
  };
  const auditService = {
    record: jest.fn(),
    recordSafely: jest.fn(),
  };
  const emailCodes = {
    issue: jest.fn().mockResolvedValue({ codeSent: true }),
  };
  const service = new AuthService(
    prisma as never,
    usersService as never,
    {} as never,
    tokenService as never,
    auditService as never,
    emailCodes as never,
    { send: jest.fn() } as never,
  );
  return { service, prisma, usersService, auditService, emailCodes };
}

describe('AuthService.register', () => {
  it('crea el usuario con el userId que generó la app (BR-06)', async () => {
    const { service, usersService } = build();
    usersService.create.mockResolvedValue({
      id: registerDto.userId,
      email: registerDto.email,
    });

    const result = await service.register(registerDto, client);

    expect(usersService.create).toHaveBeenCalledWith(
      expect.objectContaining({
        id: registerDto.userId,
        displayName: '',
        marketingOptIn: false,
      }),
      expect.anything(),
    );
    expect(result.requiresEmailVerification).toBe(true);
  });

  it('con un userId repetido responde el mismo desafío señuelo sin enviar código', async () => {
    const { service, usersService, emailCodes } = build();
    usersService.create.mockRejectedValue(
      new Prisma.PrismaClientKnownRequestError('duplicado', {
        code: 'P2002',
        clientVersion: 'test',
      }),
    );

    const result = await service.register(registerDto, client);

    expect(result).toMatchObject({
      requiresEmailVerification: true,
      requires2FA: false,
      verification: { codeSent: true },
    });
    expect(emailCodes.issue).not.toHaveBeenCalled();
  });
});

describe('AuthService.login con la cuenta bloqueada (BR-22)', () => {
  it('responde lo mismo que una contraseña incorrecta y no compara la real', async () => {
    const { service, prisma, usersService, auditService } = build();
    await service.onModuleInit();
    const realHash = await argon2.hash(
      Buffer.from(registerDto.authHash, 'base64'),
    );
    usersService.findActiveByEmail.mockResolvedValue({
      id: registerDto.userId,
      auth_hash: realHash,
      email_verified_at: new Date(),
    });
    prisma.audit_log.count.mockResolvedValue(5);

    // Contraseña correcta, pero 5 fallos recientes: 401 genérico
    await expect(
      service.login(
        {
          email: registerDto.email,
          authHash: registerDto.authHash,
          deviceName: 'Pixel',
        },
        client,
      ),
    ).rejects.toThrow(new UnauthorizedException('Credenciales inválidas.'));
    const [audited] = auditService.recordSafely.mock.calls[0] as [
      { metadata: { reason: string } },
    ];
    expect(audited.metadata.reason).toBe('account_locked');
    const [query] = prisma.audit_log.count.mock.calls[0] as [
      { where: { user_id: string; metadata: object } },
    ];
    expect(query.where.user_id).toBe(registerDto.userId);
    expect(query.where.metadata).toEqual({
      path: ['reason'],
      equals: 'invalid_credentials',
    });
  });
});
