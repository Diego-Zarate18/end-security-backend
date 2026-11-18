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

export function verificationCodeMail(
  code: string,
  minutes: number,
): RenderedMail {
  const title = 'Verifica tu correo';
  const intro = 'Usa este código para verificar el correo de tu cuenta:';
  const ignore =
    'Si no fuiste tú, ignora este mensaje; nadie podrá usar el código sin acceso a tu cuenta.';
  return {
    subject: `${code} es tu código de ${APP_NAME}`,
    html: layout(
      title,
      `<p style="margin:0">${intro}</p><p style="margin:16px 0;font-size:32px;font-weight:bold;letter-spacing:8px;font-family:'Courier New',monospace">${code}</p><p style="margin:0">Vence en ${minutes} minutos.</p><p style="margin:16px 0 0;color:#52606d">${ignore}</p>`,
    ),
    text: `${title}\n\n${intro}\n\n${code}\n\nVence en ${minutes} minutos.\n${ignore}`,
  };
}

/** Se envía cuando alguien intenta registrarse con un correo que ya tiene cuenta. */
export function registrationAttemptMail(): RenderedMail {
  const title = 'Intento de registro con tu correo';
  const body = `Alguien intentó crear una cuenta de ${APP_NAME} con este correo, que ya tiene una. No se creó nada ni cambió tu cuenta. Si fuiste tú, inicia sesión con tu contraseña maestra.`;
  return {
    subject: `${APP_NAME}: intento de registro con tu correo`,
    html: layout(title, `<p style="margin:0">${body}</p>`),
    text: `${title}\n\n${body}`,
  };
}

/** Aviso tras cambiar la contraseña maestra. */
export function passwordChangedMail(): RenderedMail {
  const title = 'Cambió tu contraseña maestra';
  const body = `La contraseña maestra de tu cuenta de ${APP_NAME} se cambió y se cerraron las sesiones de tus otros dispositivos. Si no fuiste tú, alguien tiene tu contraseña: recupera el acceso cuanto antes.`;
  return {
    subject: `${APP_NAME}: cambió tu contraseña maestra`,
    html: layout(title, `<p style="margin:0">${body}</p>`),
    text: `${title}\n\n${body}`,
  };
}

/** Aviso tras borrar la cuenta. */
export function accountDeletedMail(): RenderedMail {
  const title = 'Tu cuenta fue eliminada';
  const body = `Tu cuenta de ${APP_NAME} y tu bóveda se eliminaron de forma permanente y se cerraron todas las sesiones. Puedes volver a registrarte con este correo cuando quieras.`;
  return {
    subject: `${APP_NAME}: tu cuenta fue eliminada`,
    html: layout(title, `<p style="margin:0">${body}</p>`),
    text: `${title}\n\n${body}`,
  };
}

/** Aviso al correo actual cuando se pide cambiarlo (DEC-63). */
export function emailChangeRequestedMail(maskedNewEmail: string): RenderedMail {
  const title = 'Se pidió cambiar tu correo';
  const body = `Alguien con acceso a tu cuenta de ${APP_NAME} pidió cambiar su correo a ${maskedNewEmail}. El cambio solo se hace si se confirma el código enviado a ese correo. Si no fuiste tú, cambia tu contraseña maestra y cierra las demás sesiones.`;
  return {
    subject: `${APP_NAME}: se pidió cambiar tu correo`,
    html: layout(title, `<p style="margin:0">${body}</p>`),
    text: `${title}

${body}`,
  };
}

/** Aviso al correo anterior cuando el cambio se completa. */
export function emailChangedMail(maskedNewEmail: string): RenderedMail {
  const title = 'Cambió el correo de tu cuenta';
  const body = `El correo de tu cuenta de ${APP_NAME} ahora es ${maskedNewEmail}. Este correo ya no recibirá avisos. Si no fuiste tú, alguien tiene tu contraseña maestra.`;
  return {
    subject: `${APP_NAME}: cambió el correo de tu cuenta`,
    html: layout(title, `<p style="margin:0">${body}</p>`),
    text: `${title}

${body}`,
  };
}

/** "diego@endsecurity.com" → "di***@endsecurity.com" */
export function maskEmail(email: string): string {
  const [local, domain] = email.split('@');
  return `${local.slice(0, 2)}***@${domain}`;
}
