/** Minimal RTL helper (mirrors qrs-desktop's i18n.isRtl). */
export function isRtl(code: string): boolean {
  return code === 'ps' || code === 'fa';
}