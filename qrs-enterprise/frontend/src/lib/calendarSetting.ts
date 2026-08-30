import { useEffect, useState } from 'react';

export type CalendarId = 'gregorian' | 'jalali' | 'islamic';

export const CALENDAR_LABELS: Record<CalendarId, string> = {
  gregorian: 'Gregorian (میلادی)',
  jalali: 'Jalali (هجری شمسی)',
  islamic: 'Islamic (هجری قمری)',
};

const KEY = 'qrs.calendar';
const EVENT = 'qrs:calendar';

/** The user's preferred calendar, used by every date input in the app. */
export function getCalendar(): CalendarId {
  try {
    const v = localStorage.getItem(KEY);
    if (v === 'gregorian' || v === 'jalali' || v === 'islamic') return v;
  } catch {
    /* ignore */
  }
  return 'gregorian';
}

export function setCalendar(c: CalendarId): void {
  try {
    localStorage.setItem(KEY, c);
  } catch {
    /* ignore */
  }
  window.dispatchEvent(new Event(EVENT));
}

/** React hook that tracks the global calendar preference. */
export function useCalendar(): CalendarId {
  const [c, setC] = useState<CalendarId>(getCalendar());
  useEffect(() => {
    const handler = (): void => setC(getCalendar());
    window.addEventListener(EVENT, handler);
    return () => window.removeEventListener(EVENT, handler);
  }, []);
  return c;
}