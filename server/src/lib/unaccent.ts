/**
 * Strips diacritical marks (accents) from a string.
 * Used for accent-insensitive search queries in place of the PostgreSQL f_unaccent extension.
 *
 * Example: unaccent('café') → 'cafe'
 */
export function unaccent(str: string): string {
  return str.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}
