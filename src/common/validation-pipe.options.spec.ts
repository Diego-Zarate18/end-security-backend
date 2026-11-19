import { IsInt } from 'class-validator';
import { ArgumentMetadata, ValidationPipe } from '@nestjs/common';
import { SyncQueryDto } from '../modules/vault/dto/sync-vault.dto';
import { validationPipeOptions } from './validation-pipe.options';

describe('validationPipeOptions (F-03)', () => {
  const pipe = new ValidationPipe(validationPipeOptions);
  const meta: ArgumentMetadata = { type: 'query', metatype: SyncQueryDto };

  it('convierte el query con @Type explícito', async () => {
    await expect(pipe.transform({ since: '5' }, meta)).resolves.toMatchObject({
      since: 5,
    });
  });

  it('rechaza un string donde el body espera entero (sin coerción implícita)', async () => {
    class BodyDto {
      @IsInt()
      n!: number;
    }
    await expect(
      pipe.transform({ n: '5' }, { type: 'body', metatype: BodyDto }),
    ).rejects.toThrow();
  });
});
