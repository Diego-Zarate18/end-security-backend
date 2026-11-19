import { ServiceUnavailableException } from '@nestjs/common';
import { AppService } from './app.service';

describe('AppService.checkHealth', () => {
  it('responde ok sin versiones ni detalles cuando la base contesta', async () => {
    const service = new AppService({
      $queryRaw: jest.fn().mockResolvedValue([{ '?column?': 1 }]),
    } as never);

    await expect(service.checkHealth()).resolves.toEqual({ status: 'ok' });
  });

  it('responde 503 si la base no contesta', async () => {
    const service = new AppService({
      $queryRaw: jest.fn().mockRejectedValue(new Error('conexión rechazada')),
    } as never);

    await expect(service.checkHealth()).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
  });
});
