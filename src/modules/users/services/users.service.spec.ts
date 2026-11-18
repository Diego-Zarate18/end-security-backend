import { UNVERIFIED_TTL_MS, UsersService } from './users.service';

const client = { ipAddress: '203.0.113.9', userAgent: 'jest' };
const userId = '3f2504e0-4f89-41d3-9a0c-0305e82c3301';

function build(count: number) {
  const tx = {
    users: { updateMany: jest.fn().mockResolvedValue({ count }) },
    email_verifications: { deleteMany: jest.fn() },
    audit_log_pii: { deleteMany: jest.fn() },
    sessions: { deleteMany: jest.fn() },
  };
  const prisma = {
    $transaction: jest.fn((cb: (t: typeof tx) => unknown) => cb(tx)),
  };
  const audit = { record: jest.fn() };
  const service = new UsersService(prisma as never, audit as never);
  return { service, tx, audit };
}

describe('UsersService.anonymizeIfExpiredUnverified', () => {
  it('el UPDATE solo alcanza cuentas sin verificar, vivas, sin bóveda y de más de 24 h', async () => {
    const { service, tx } = build(0);
    const before = Date.now();

    await service.anonymizeIfExpiredUnverified(userId, client);

    const [query] = tx.users.updateMany.mock.calls[0] as [
      { where: Record<string, unknown> },
    ];
    expect(query.where).toMatchObject({
      id: userId,
      email_verified_at: null,
      deleted_at: null,
      vault_items: { none: {} },
    });
    const cutoff = (query.where.created_at as { lt: Date }).lt.getTime();
    expect(cutoff).toBeLessThanOrEqual(before - UNVERIFIED_TTL_MS + 1000);
    expect(cutoff).toBeGreaterThan(before - UNVERIFIED_TTL_MS - 5000);
  });

  it('si el UPDATE no afecta ninguna fila (vigente, verificada o con bóveda) no toca nada más', async () => {
    const { service, tx, audit } = build(0);

    await expect(
      service.anonymizeIfExpiredUnverified(userId, client),
    ).resolves.toBe(false);

    expect(audit.record).not.toHaveBeenCalled();
    expect(tx.sessions.deleteMany).not.toHaveBeenCalled();
    expect(tx.email_verifications.deleteMany).not.toHaveBeenCalled();
  });

  it('si reemplaza: anonimiza, audita y borra sus hijas', async () => {
    const { service, tx, audit } = build(1);

    await expect(
      service.anonymizeIfExpiredUnverified(userId, client),
    ).resolves.toBe(true);

    const [query] = tx.users.updateMany.mock.calls[0] as [
      { data: Record<string, unknown> },
    ];
    expect(query.data).toMatchObject({
      display_name: 'Cuenta eliminada',
      auth_hash: '!deleted',
      email_verified_at: null,
    });
    expect(String(query.data.email)).toMatch(/^deleted\+.+@deleted\.invalid$/);
    expect(audit.record).toHaveBeenCalledWith(
      expect.objectContaining({
        userId,
        metadata: { reason: 'unverified_expired' },
      }),
      tx,
    );
    expect(tx.email_verifications.deleteMany).toHaveBeenCalled();
    expect(tx.audit_log_pii.deleteMany).toHaveBeenCalled();
    expect(tx.sessions.deleteMany).toHaveBeenCalled();
  });
});
