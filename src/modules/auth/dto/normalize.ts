import { TransformFnParams } from 'class-transformer';

/** Igual en DTO y servicio (DEC-63): recortar, minúsculas y NFC. */
export const normalizeEmailText = (email: string): string =>
  email.trim().toLowerCase().normalize('NFC');

export const normalizeEmail = ({ value }: TransformFnParams): unknown =>
  typeof value === 'string' ? normalizeEmailText(value) : value;

export const trimString = ({ value }: TransformFnParams): unknown =>
  typeof value === 'string' ? value.trim() : value;
