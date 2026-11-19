import { randomBytes } from 'crypto';
import { validateEnv } from './env.validation';

const secret = () => randomBytes(24).toString('hex');

/** Un entorno de producción bueno; cada prueba le quita o cambia una cosa. */
function production(overrides: Record<string, unknown> = {}) {
  return {
    NODE_ENV: 'production',
    DATABASE_URL: 'postgresql://usuario@localhost:5432/prueba',
    JWT_SECRET: secret(),
    JWT_REFRESH_SECRET: secret(),
    AUDIT_HMAC_KEY: secret(),
    TOTP_ENCRYPTION_KEYS: `1:${randomBytes(32).toString('base64')}`,
    RESEND_API_KEY: 're_clave_de_prueba',
    EMAIL_FROM: 'End Security <no-reply@example.com>',
    TRUST_PROXY: '1',
    ...overrides,
  };
}

function without(name: string) {
  const env = production();
  delete (env as Record<string, unknown>)[name];
  return env;
}

describe('validateEnv en producción', () => {
  it('acepta un entorno completo', () => {
    expect(() => validateEnv(production())).not.toThrow();
  });

  it.each([
    'RESEND_API_KEY',
    'EMAIL_FROM',
    'TOTP_ENCRYPTION_KEYS',
    'DATABASE_URL',
  ])('se niega a arrancar sin %s', (name) => {
    expect(() => validateEnv(without(name))).toThrow();
  });

  it('rechaza una RESEND_API_KEY vacía o un EMAIL_FROM en blanco', () => {
    expect(() => validateEnv(production({ RESEND_API_KEY: '' }))).toThrow(
      /RESEND_API_KEY/,
    );
    expect(() => validateEnv(production({ EMAIL_FROM: '  ' }))).toThrow(
      /EMAIL_FROM/,
    );
  });

  it.each(['JWT_SECRET', 'JWT_REFRESH_SECRET', 'AUDIT_HMAC_KEY'])(
    'rechaza %s de menos de 32 caracteres o con el valor de ejemplo',
    (name) => {
      expect(() => validateEnv(production({ [name]: 'corta' }))).toThrow();
      expect(() =>
        validateEnv(
          production({ [name]: 'change_in_production_'.padEnd(40, 'x') }),
        ),
      ).toThrow(/distintos|propios/);
    },
  );

  it('rechaza JWT_SECRET igual a JWT_REFRESH_SECRET', () => {
    const same = secret();
    expect(() =>
      validateEnv(production({ JWT_SECRET: same, JWT_REFRESH_SECRET: same })),
    ).toThrow(/distintos/);
  });

  it('rechaza CORS_ORIGIN=*', () => {
    expect(() => validateEnv(production({ CORS_ORIGIN: '*' }))).toThrow(
      /CORS_ORIGIN/,
    );
  });

  it('sin CORS_ORIGIN no abre ningún origen', () => {
    expect(validateEnv(production()).CORS_ORIGIN).toBe('');
    expect(
      validateEnv(production({ CORS_ORIGIN: 'https://ejemplo.com' }))
        .CORS_ORIGIN,
    ).toBe('https://ejemplo.com');
  });

  it('el mensaje de error no imprime valores', () => {
    const bad = secret();
    let message = '';
    try {
      validateEnv(production({ JWT_SECRET: bad, JWT_REFRESH_SECRET: bad }));
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain('JWT_SECRET');
    expect(message).not.toContain(bad);
  });
});

describe('validateEnv fuera de producción', () => {
  it('sin RESEND_API_KEY ni EMAIL_FROM sigue arrancando (los correos van a la consola)', () => {
    const env = production({ NODE_ENV: 'development' });
    delete (env as Record<string, unknown>).RESEND_API_KEY;
    delete (env as Record<string, unknown>).EMAIL_FROM;
    expect(() => validateEnv(env)).not.toThrow();
  });
});
