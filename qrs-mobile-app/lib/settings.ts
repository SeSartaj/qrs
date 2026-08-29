import AsyncStorage from '@react-native-async-storage/async-storage';
import { convertDateParts, formatDate as formatCalendarDate } from 'tri-calendar';

export type LanguageCode = 'en' | 'ps' | 'fa';
export type DateFormat = 'gregorian' | 'jalali' | 'islamic';
export type TrustPolicy = 'any' | 'all';
export interface AppSettings { language: LanguageCode; dateFormat: DateFormat; trustPolicy: TrustPolicy; }
const KEY = 'qrs.settings';
export const LANGUAGES = [{ code: 'en', label: 'English' }, { code: 'ps', label: 'پښتو' }, { code: 'fa', label: 'فارسی' }];
export const DATE_FORMATS = [{ code: 'gregorian', label: 'Gregorian' }, { code: 'jalali', label: 'Jalali' }, { code: 'islamic', label: 'Islamic' }];
export const TRUST_POLICIES: Array<{ code: TrustPolicy; label: string; description: string }> = [{ code: 'any', label: 'Any trusted CA', description: 'Accept when at least one trusted CA verifies the issuer.' }, { code: 'all', label: 'All trusted CAs', description: 'Require every trusted CA to verify the issuer.' }];
export function isRtl(language: LanguageCode): boolean { return language === 'ps' || language === 'fa'; }
export async function getSettings(): Promise<AppSettings> {
  try { return { language: 'en', dateFormat: 'gregorian', trustPolicy: 'any', ...JSON.parse((await AsyncStorage.getItem(KEY)) ?? '{}') }; } catch { return { language: 'en', dateFormat: 'gregorian', trustPolicy: 'any' }; }
}
export async function setSettings(settings: AppSettings): Promise<void> { await AsyncStorage.setItem(KEY, JSON.stringify(settings)); }
export function formatEpoch(epoch: number | undefined, format: DateFormat = 'gregorian'): string {
  if (epoch === undefined) return '—';
  const d = new Date(epoch * 1000);
  const parts = convertDateParts({ year: d.getFullYear(), month: d.getMonth() + 1, day: d.getDate() }, 'gregorian', format);
  return `${formatCalendarDate(parts, format, 'D MMMM YYYY', format === 'gregorian' ? 'en' : 'prs', format === 'gregorian' ? 'latn' : 'arabext')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}
export function formatMs(ms: number | undefined, format: DateFormat): string { return formatEpoch(ms === undefined ? undefined : Math.floor(ms / 1000), format); }
export function selectV2Option(value: unknown, options: unknown): string { const i = typeof value === 'number' ? value : -1; const o = Array.isArray(options) ? options[i] : undefined; return typeof o === 'string' ? o : (o as { label?: string } | undefined)?.label ?? String(value); }
export function formatFieldValue(type: string, value: unknown, options: unknown, format: DateFormat): string { if (type === 'datetimeEpoch' && typeof value === 'number') return formatEpoch(value, format); if (type === 'selectv2') return selectV2Option(value, options); return value == null ? '—' : String(value); }
