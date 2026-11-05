const APP_NAME = 'End Security';

interface RenderedMail {
  subject: string;
  html: string;
  text: string;
}

const layout = (title: string, body: string) => `<!doctype html>
<html lang="es">
  <body style="margin:0;padding:24px;background:#f4f5f7;font-family:Arial,Helvetica,sans-serif;color:#1f2933">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:8px;padding:32px">
      <tr><td>
        <p style="margin:0 0 8px;font-size:14px;color:#52606d">${APP_NAME}</p>
        <h1 style="margin:0 0 16px;font-size:20px">${title}</h1>
        ${body}
        <p style="margin:24px 0 0;font-size:12px;color:#7b8794">Nunca te pediremos tu contraseña maestra por correo.</p>
      </td></tr>
    </table>
  </body>
</html>`;

const codeBlock = (code: string) =>
  `<p style="margin:16px 0;font-size:32px;font-weight:bold;letter-spacing:8px;font-family:'Courier New',monospace">${code}</p>`;

export function verificationCodeMail(
  code: string,
  minutes: number,
  purpose: 'verify_email' | 'change_email',
): RenderedMail {
  const verifying = purpose === 'verify_email';
  const title = verifying ? 'Verifica tu correo' : 'Confirma tu nuevo correo';
  const intro = verifying
    ? 'Usa este código para verificar el correo de tu cuenta:'
    : 'Usa este código para confirmar el cambio del correo de tu cuenta a esta dirección:';
  const ignore =
    'Si no fuiste tú, ignora este mensaje; nadie podrá usar el código sin acceso a tu cuenta.';
  return {
    subject: `${code} es tu código de ${APP_NAME}`,
    html: layout(
      title,
      `<p style="margin:0">${intro}</p>${codeBlock(code)}<p style="margin:0">Vence en ${minutes} minutos.</p><p style="margin:16px 0 0;color:#52606d">${ignore}</p>`,
    ),
    text: `${title}\n\n${intro}\n\n${code}\n\nVence en ${minutes} minutos.\n${ignore}`,
  };
}

export function emailChangedNoticeMail(newEmail: string): RenderedMail {
  const masked = maskEmail(newEmail);
  const title = 'Cambió el correo de tu cuenta';
  const body = `El correo de tu cuenta de ${APP_NAME} se cambió a ${masked} y se cerraron las sesiones de tus otros dispositivos. Si no fuiste tú, contacta al soporte de inmediato.`;
  return {
    subject: `${APP_NAME}: el correo de tu cuenta cambió`,
    html: layout(title, `<p style="margin:0">${body}</p>`),
    text: `${title}\n\n${body}`,
  };
}

/** "diego@endsecurity.com" → "di***@endsecurity.com" */
export function maskEmail(email: string): string {
  const [local, domain] = email.split('@');
  return `${local.slice(0, 2)}***@${domain}`;
}
