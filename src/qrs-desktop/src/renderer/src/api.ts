import type { QrsApi } from '@shared/types';
import { convertDateParts, formatDate as formatCalendarDate } from 'tri-calendar';
import { getCalendar } from './calendarSetting';

/** Typed access to the preload bridge. */
export function qrs(): QrsApi {
  return window.qrs;
}

export type SafeResult<T> = { ok: true; value: T } | { ok: false; error: string };

/** Await a promise and normalise failures into a message. */
export async function safe<T>(p: Promise<T>): Promise<SafeResult<T>> {
  try {
    return { ok: true, value: await p };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

/** Human-readable short id (first 8 chars + …). */
export function shortId(id: string): string {
  if (id.length <= 12) return id;
  return `${id.slice(0, 8)}…${id.slice(-4)}`;
}

export function formatDate(epoch: number | undefined): string {
  if (epoch === undefined) return '—';
  const date = new Date(epoch * 1000);
  const calendar = getCalendar();
  try {
    const parts = convertDateParts(
      { year: date.getFullYear(), month: date.getMonth() + 1, day: date.getDate() },
      'gregorian',
      calendar
    );
    const rtl = document.documentElement.lang === 'fa' || document.documentElement.lang === 'ps';
    const locale = calendar === 'gregorian' ? 'en' : 'prs';
    const dateText = formatCalendarDate(parts, calendar, 'D MMMM YYYY', locale, rtl ? 'arabext' : 'latn');
    const time = `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`;
    const localizedTime = rtl ? time.replace(/[0-9]/g, (digit) => '۰۱۲۳۴۵۶۷۸۹'[Number(digit)]) : time;
    return `${dateText} ${localizedTime}`;
  } catch {
    return date.toLocaleString();
  }
}

/** Encode bytes as unpadded base64url (chunked to avoid stack overflow on big files). */
export function bytesToBase64Url(bytes: Uint8Array): string {
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** SHA-256 of a byte array, as lowercase hex. */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const copy = new Uint8Array(bytes); // fresh ArrayBuffer (byteOffset 0)
  const digest = await crypto.subtle.digest('SHA-256', copy.buffer as ArrayBuffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
