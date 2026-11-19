import {
  formatSyslog,
  Severity,
  severityFor,
  toCode,
  truncateIp,
} from './syslog';

describe('syslog RFC 5424 (BR-25, DEC-62)', () => {
  it('arma la línea con PRI local0, MSGID y datos estructurados', () => {
    const line = formatSyslog(
      Severity.Warning,
      'login',
      {
        req: 'abc',
        status: 401,
        code: 'unauthorized',
        ms: 12,
        ip: '203.0.113.0/24',
      },
      'POST /api/auth/login',
      new Date('2026-11-18T07:58:03.412Z'),
    );
    expect(line).toMatch(
      /^<132>1 2026-11-18T07:58:03\.412Z \S+ endsec-api \d+ login \[endsec@32473 req="abc" status="401" code="unauthorized" ms="12" ip="203\.0\.113\.0\/24"\] POST \/api\/auth\/login$/,
    );
  });

  it('escapa comillas, barras y corchetes, y omite campos vacíos', () => {
    const line = formatSyslog(
      Severity.Info,
      'http',
      { req: 'a"b]c\\', user: undefined },
      'x',
    );
    expect(line).toContain('[endsec@32473 req="a\\"b\\]c\\\\"]');
    expect(line).not.toContain('user=');
  });

  it('sin datos estructurados usa el guion de RFC 5424', () => {
    expect(formatSyslog(Severity.Notice, 'startup', {}, 'ok')).toMatch(
      /^<133>1 .* startup - ok$/,
    );
  });

  it.each([
    ['203.0.113.77', '203.0.113.0/24'],
    ['::ffff:198.51.100.9', '198.51.100.0/24'],
    ['2001:db8:85a3::8a2e:370:7334', '2001:db8:85a3::/48'],
    ['2001:db8::1', '2001:db8:0::/48'],
    ['basura', undefined],
  ])('trunca la IP %s → %s', (ip, expected) => {
    expect(truncateIp(ip)).toBe(expected);
  });

  it('elige la severidad por resultado y operación', () => {
    expect(severityFor(503, 'login')).toBe(Severity.Err);
    expect(severityFor(401, 'login')).toBe(Severity.Warning);
    expect(severityFor(200, 'login')).toBe(Severity.Notice);
    expect(severityFor(200, 'vault_pull')).toBe(Severity.Info);
  });

  it('convierte el nombre del error en code', () => {
    expect(toCode('InvalidCode')).toBe('invalid_code');
    expect(toCode('Bad Request')).toBe('bad_request');
  });
});
