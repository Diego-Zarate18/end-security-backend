import type { ValidationPipeOptions } from '@nestjs/common';

/** Sin conversión implícita (F-03): "5" no pasa por número; los query usan @Type explícito. */
export const validationPipeOptions: ValidationPipeOptions = {
  whitelist: true,
  forbidNonWhitelisted: true,
  transform: true,
};
