import { TransformFnParams } from 'class-transformer';

export const normalizeEmail = ({ value }: TransformFnParams): unknown =>
  typeof value === 'string'
    ? value.trim().toLowerCase().normalize('NFC')
    : value;

export const trimString = ({ value }: TransformFnParams): unknown =>
  typeof value === 'string' ? value.trim() : value;
