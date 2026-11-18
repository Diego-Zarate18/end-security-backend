import { BadRequestException } from '@nestjs/common';
import { AccountService, emailChangeAllowedAt } from './account.service';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const NOW = Date.UTC(2026, 10, 18, 12);

describe('emailChangeAllowedAt (DEC-63, BR-17)', () => {
  it('permite cambiar sin solicitudes ni cambios recientes', () => {
    expect(emailChangeAllowedAt([], [], null)).toBe(0);
  });

  it('3 solicitudes en la última hora: espera a que salga la más vieja', () => {
    const hour = [NOW - 50 * 60_000, NOW - 20 * 60_000, NOW - 5 * 60_000];
    expect(emailChangeAllowedAt(hour, hour, null)).toBe(hour[0] + HOUR);
  });

  it('2 en la última hora no bloquean', () => {
    const hour = [NOW - 20 * 60_000, NOW - 5 * 60_000];
    expect(emailChangeAllowedAt(hour, hour, null)).toBeLessThanOrEqual(NOW);
  });

  it('5 en el día bloquean hasta 24 h después de la más vieja de las 5', () => {
    const day = [20, 15, 10, 6, 3].map((h) => NOW - h * HOUR);
    expect(emailChangeAllowedAt(day, [], null)).toBe(day[0] + DAY);
  });

  it('un cambio completado hace 2 h obliga a esperar 22 h', () => {
    expect(emailChangeAllowedAt([], [], NOW - 2 * HOUR) - NOW).toBe(22 * HOUR);
  });
});

describe('AccountService.requestEmailChange', () => {
  it('rechaza el mismo correo con 400 antes de pedir la reautenticación', async () => {
    const reauth = { verify: jest.fn() };
    const usersService = {
      findActiveById: jest
        .fn()
        .mockResolvedValue({ id: 'u1', email: 'ana@example.com' }),
    };
    const service = new AccountService(
      {} as never,
      usersService as never,
      reauth as never,
      {} as never,
      {} as never,
      {} as never,
    );
    const actor = {
      userId: 'u1',
      sessionId: 's1',
      client: { ipAddress: '1.2.3.4', userAgent: 'jest' },
    };

    await expect(
      service.requestEmailChange(actor, {
        newEmail: 'ana@example.com',
        authHash: 'x',
      }),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(reauth.verify).not.toHaveBeenCalled();
  });
});
