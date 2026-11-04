import { registerDecorator, ValidationOptions } from 'class-validator';

const STRICT_BASE64 =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * Valida que el valor sea base64 estricto y que, decodificado, mida entre
 * `minBytes` y `maxBytes`. Evita aceptar material criptográfico truncado o
 * cargas desproporcionadas.
 */
export function IsBase64Bytes(
  minBytes: number,
  maxBytes: number,
  options?: ValidationOptions,
) {
  return (object: object, propertyName: string) => {
    registerDecorator({
      name: 'isBase64Bytes',
      target: object.constructor,
      propertyName,
      constraints: [minBytes, maxBytes],
      options: {
        message: `${propertyName} debe ser base64 válido de ${minBytes} a ${maxBytes} bytes.`,
        ...options,
      },
      validator: {
        validate(value: unknown): boolean {
          if (typeof value !== 'string' || !STRICT_BASE64.test(value)) {
            return false;
          }
          const length = Buffer.byteLength(value, 'base64');
          return length >= minBytes && length <= maxBytes;
        },
      },
    });
  };
}
