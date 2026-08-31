import { useMemo } from 'react';
import { Box, TextField } from '@mui/material';

import { CalendarPicker } from './CalendarPicker';
import { convertDate } from 'tri-calendar';
import { useCalendar } from '../calendarSetting';
import { isRtl } from '../i18n';

/** Convert a local datetime string (YYYY-MM-DDTHH:mm) to UTC epoch seconds. */
export function localDateTimeToEpoch(local: string): number {
  return Math.floor(new Date(local).getTime() / 1000);
}

/** Convert UTC epoch seconds to a local datetime string (YYYY-MM-DDTHH:mm). */
export function epochToLocalDateTime(epoch: number): string {
  const d = new Date(epoch * 1000);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

interface Props {
  label: string;
  kind: 'date' | 'datetime' | 'datetimeEpoch';
  /** Used by the certificate validity date controls, which store date-only epochs. */
  epoch?: boolean;
  value?: number | string;
  onChange: (value: number | string | undefined) => void;
  helperText?: string;
  fullWidth?: boolean;
  disabled?: boolean;
  autoFocus?: boolean;
}

/**
 * A datetime picker that opens a calendar rendered in the app-wide calendar
 * setting (Gregorian / Jalali / Islamic) via `tri-calendar`, plus a local-time
 * input. The value reported is UTC epoch seconds; only the stored value is UTC.
 */
export function FlexDateTimeInput({ label, kind, epoch = kind === 'datetimeEpoch', value, onChange, helperText, fullWidth, disabled, autoFocus }: Props) {
  const calendar = useCalendar();
  const rtl = isRtl(document.documentElement.lang);

  // The current value as a gregorian local Date (for the picker + display).
  const currentDate = useMemo<Date | null>(() => {
    if (value === undefined || (typeof value === 'number' && !Number.isFinite(value))) return null;
    if (typeof value === 'number') return new Date(value * 1000);
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }, [value]);

  // Show the date in the selected calendar for the text field.
  const shownInCalendar = useMemo(() => {
    if (currentDate === null) return '';
    const g = `${currentDate.getFullYear()}-${String(currentDate.getMonth() + 1).padStart(2, '0')}-${String(
      currentDate.getDate()
    ).padStart(2, '0')}`;
    try {
      const shownDate = convertDate(g, { from: 'gregorian', to: calendar, format: 'YYYY/MM/DD', locale: calendar === 'gregorian' ? 'en' : 'prs' }) as string;
      if (kind === 'date' || kind === 'datetimeEpoch') return shownDate;
      return `${shownDate} ${String(currentDate.getHours()).padStart(2, '0')}:${String(currentDate.getMinutes()).padStart(2, '0')}`;
    } catch {
      return g;
    }
  }, [currentDate, calendar, kind]);

  const emit = (date: Date): void => {
    const seconds = Math.floor(date.getTime() / 1000);
    if (kind === 'date' && !epoch) {
      const g = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
      onChange(g);
    } else {
      onChange(epoch ? seconds : new Date(date.getTime()).toISOString().replace('.000Z', 'Z'));
    }
  };

  const handleSelectDate = (d: Date): void => {
    // The library reports both calendar and time changes through this callback.
    // Preserve the exact Date it gives us so time spinner changes are not lost.
    emit(d);
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', gap: 1, alignItems: 'flex-start' }}>
        
      <CalendarPicker calendar={calendar} value={currentDate ?? new Date()} showTime={kind !== 'date'} popup onSelect={handleSelectDate} trigger={(openCalendar) => (
          <TextField
            label={label}
            value={shownInCalendar}
            onClick={openCalendar}
            onKeyDown={(event) => { if (event.key === ' ') { event.preventDefault(); openCalendar(); } }}
            placeholder="Pick a date"
            helperText={
              helperText ??
              (kind === 'datetimeEpoch' && currentDate
                ? `Time: ${String(currentDate.getHours()).padStart(2, '0')}:${String(currentDate.getMinutes()).padStart(2, '0')}`
                : kind === 'date'
                  ? 'Select a date.'
                  : 'Select a date and time.')
            }
            fullWidth={fullWidth}
            disabled={disabled}
            autoFocus={autoFocus}
            slotProps={{
              htmlInput: {
                readOnly: true,
                dir: rtl ? 'rtl' : 'rtl',
              },
            }}
            sx={{
              flexGrow: 1,
              '& .MuiInputBase-input': {
                direction: rtl ? 'rtl' : 'ltr',
                textAlign: rtl ? 'right' : 'left',
              },
            }}
          />
        )}
        />
      </Box>
    </Box>
  );
}
