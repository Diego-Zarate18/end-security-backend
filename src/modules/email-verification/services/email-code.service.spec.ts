import { HttpException } from '@nestjs/common';
import {
  EmailCodeService,
  RESEND_PER_DAY,
  RESEND_PER_HOUR,
  resendCapAllowedAt,
} from './email-code.service';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const client = { ipAddress: '203.0.113.9', userAgent: 'jest' };
const actor = { userId: '3f2504e0-4f89-41d3-9a0c-0305e82c3301', client };

describe('resendCapAllowedAt', () => {
  const now = 1_000_000_000_000;

  it('sin tope hasta 4 envíos en la hora', () => {
    expect(resendCapAllowedAt([])).toBe(0);
    expect(resendCapAllowedAt([4, 3, 2, 1].map((m) => now - m * 60_000))).toBe(
      0,
    );
  });

  it('con 5 en la hora, espera hasta que el más viejo cumpla la hora', () => {
    const sends = [50, 40, 30, 20, 10].map((m) => now - m * 60_000);
    expect(resendCapAllowedAt(sends)).toBe(sends[0] + HOUR);
  });

  it('5 envíos de hace más de una hora ya no cuentan', () => {
    const sends = [200, 190, 180, 170, 160].map((m) => now - m * 60_000);
    expect(resendCapAllowedAt(sends)).toBeLessThan(now);
  });

  it('con 10 en el día espera hasta que el más viejo cumpla el día', () => {
    const sends = Array.from(
      { length: RESEND_PER_DAY },
      (_, i) => now - DAY + 600_000 + i * 2 * HOUR,
    );
    expect(resendCapAllowedAt(sends)).toBe(sends[0] + DAY);
  });
});

describe('EmailCodeService.issue (tope del código de registro)', () => {
  function build(rows: Date[]) {
    const prisma = {
      email_verifications: {
        findFirst: jest.fn().mockResolvedValue(null),
        findMany: jest
          .fn()
          .mockResolvedValue(rows.map((created_at) => ({ created_at }))),
        updateMany: jest.fn(),
        create: jest.fn(),
      },
      $transaction: jest.fn().mockResolvedValue([]),
    };
    const mail = { send: jest.fn() };
    const audit = { record: jest.fn(), recordSafely: jest.fn() };
    const config = { getOrThrow: () => 'pepper-de-prueba' };
    const service = new EmailCodeService(
      prisma as never,
      mail as never,
      audit as never,
      config as never,
    );
    return { service, prisma, mail };
  }

  it('al llegar a 5 en la hora responde 429 con retryAfterSeconds y no envía', async () => {
    const rows = Array.from(
      { length: RESEND_PER_HOUR },
      (_, i) => new Date(Date.now() - (50 - i * 10) * 60_000),
    );
    const { service, mail, prisma } = build(rows);

    const error = await service
      .issue(actor, 'ana@example.com')
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(HttpException);
    const http = error as HttpException;
    expect(http.getStatus()).toBe(429);
    const { details } = http.getResponse() as {
      details: { retryAfterSeconds: number };
    };
    expect(details.retryAfterSeconds).toBeGreaterThan(0);
    expect(details.retryAfterSeconds).toBeLessThanOrEqual(600);
    expect(mail.send).not.toHaveBeenCalled();
    expect(prisma.$transaction).not.toHaveBeenCalled();
  });

  it('con 4 en la hora envía', async () => {
    const rows = [40, 30, 20, 10].map((m) => new Date(Date.now() - m * 60_000));
    const { service, mail } = build(rows);
    await service.issue(actor, 'ana@example.com');
    expect(mail.send).toHaveBeenCalledTimes(1);
  });

  it('el cambio de correo no usa este tope (tiene el suyo, DEC-63)', async () => {
    const { service, prisma, mail } = build([]);
    await service.issue(actor, 'nuevo@example.com', {
      purpose: 'change_email',
    });
    expect(prisma.email_verifications.findMany).not.toHaveBeenCalled();
    expect(mail.send).toHaveBeenCalledTimes(1);
  });
});
