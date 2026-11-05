import {
  Injectable,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Resend } from 'resend';

export interface MailMessage {
  to: string;
  subject: string;
  html: string;
  text: string;
  /** Evita correos duplicados si la petición se reintenta (Resend lo guarda 24 h). */
  idempotencyKey?: string;
}

/**
 * Envío de correo transaccional con Resend.
 *
 * Sin RESEND_API_KEY (solo fuera de producción) el correo no sale: se escribe
 * en la consola del servidor para poder probar sin gastar la cuota.
 */
@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  private readonly resend: Resend | null;
  private readonly from: string;

  constructor(configService: ConfigService) {
    const apiKey = configService.get<string>('RESEND_API_KEY');
    this.resend = apiKey ? new Resend(apiKey) : null;
    this.from = configService.getOrThrow<string>('EMAIL_FROM');
    if (!this.resend) {
      this.logger.warn(
        'RESEND_API_KEY no configurada: los correos se mostrarán en la consola.',
      );
    }
  }

  async send(message: MailMessage): Promise<void> {
    if (!this.resend) {
      this.logger.log(
        `[MailDev] Para: ${message.to} | Asunto: ${message.subject}\n${message.text}`,
      );
      return;
    }

    let failure: string | null = null;
    try {
      const { error } = await this.resend.emails.send(
        {
          from: this.from,
          to: [message.to],
          subject: message.subject,
          html: message.html,
          text: message.text,
        },
        message.idempotencyKey
          ? { idempotencyKey: message.idempotencyKey }
          : undefined,
      );
      if (error) failure = `${error.name}: ${error.message}`;
    } catch (error) {
      // Errores de red o del SDK
      failure = error instanceof Error ? error.message : String(error);
    }

    if (failure) {
      // El detalle va al log del servidor; el cliente recibe un mensaje genérico
      this.logger.error(`[MailError] ${failure}`);
      throw new ServiceUnavailableException(
        'No se pudo enviar el correo. Intenta de nuevo en unos minutos.',
      );
    }
  }
}
