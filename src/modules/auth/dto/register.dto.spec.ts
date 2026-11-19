import { plainToInstance } from 'class-transformer';
import { validateSync } from 'class-validator';
import { RegisterDto } from './register.dto';

const b64 = (bytes: number) => Buffer.alloc(bytes, 7).toString('base64');

const valid = () => ({
  userId: '3F2504E0-4F89-41D3-9A0C-0305E82C3301',
  email: '  Ana@Example.com ',
  authHash: b64(32),
  kdf: { salt: b64(16), memoryKib: 65536, iterations: 3, parallelism: 1 },
  pvk: { ciphertext: b64(48), nonce: b64(12) },
  deviceName: 'Pixel',
});

const errorsOf = (body: object) =>
  validateSync(plainToInstance(RegisterDto, body)).map((e) => e.property);

describe('RegisterDto', () => {
  it('acepta el registro de la app sin displayName ni marketingOptIn (BR-07, BR-16)', () => {
    expect(errorsOf(valid())).toEqual([]);
  });

  it('exige el userId de la app y lo deja en minúsculas (BR-06)', () => {
    expect(errorsOf({ ...valid(), userId: undefined })).toContain('userId');
    expect(errorsOf({ ...valid(), userId: 'no-es-uuid' })).toContain('userId');
    const dto = plainToInstance(RegisterDto, valid());
    expect(dto.userId).toBe('3f2504e0-4f89-41d3-9a0c-0305e82c3301');
  });

  it.each([
    ['memoryKib', 65535],
    ['iterations', 2],
    ['parallelism', 4],
  ])('rechaza %s=%d por debajo del piso de DEC-05 (BR-23)', (field, value) => {
    const body = valid();
    expect(
      errorsOf({ ...body, kdf: { ...body.kdf, [field]: value } }),
    ).toContain('kdf');
  });

  it('normaliza el correo: recorta, minúsculas y NFC (DEC-63)', () => {
    const decomposed = 'josé@example.com';
    const dto = plainToInstance(RegisterDto, { ...valid(), email: decomposed });
    expect(dto.email).toBe('josé@example.com');
    expect(plainToInstance(RegisterDto, valid()).email).toBe('ana@example.com');
  });
});
