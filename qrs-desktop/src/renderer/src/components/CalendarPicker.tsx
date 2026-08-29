import DatePicker, { Calendar } from 'react-multi-date-picker';
import 'react-multi-date-picker/styles/backgrounds/bg-dark.css';
import TimePicker from 'react-multi-date-picker/plugins/time_picker';
import { useTheme } from '@mui/material/styles';
import persian from 'react-date-object/calendars/persian';
import persian_fa from 'react-date-object/locales/persian_fa';
import arabic from 'react-date-object/calendars/arabic';
import arabic_ar from 'react-date-object/locales/arabic_ar';
import type { ReactNode } from 'react';
import type { Calendar as TriCalendar } from 'tri-calendar';

interface Props {
  calendar: TriCalendar;
  value?: Date;
  onSelect: (gregorian: Date) => void;
  showTime?: boolean;
  popup?: boolean;
  trigger?: (open: () => void) => ReactNode;
}

// Afghan Solar Hijri month names (used instead of the Iranian Persian names).
export const AFGHAN_MONTHS = [
  ['حمل', 'Hamal'], ['ثور', 'Sawr'], ['جوزا', 'Jawza'], ['سرطان', 'Saratan'],
  ['اسد', 'Asad'], ['سنبله', 'Sunbula'], ['میزان', 'Mizan'], ['عقرب', 'Aqrab'],
  ['قوس', 'Qaws'], ['جدی', 'Jaddi'], ['دلو', 'Dalw'], ['حوت', 'Hoot'],
];

/** Shared library-backed calendar renderer for date and datetime fields. */
export function CalendarPicker({ calendar, value, onSelect, showTime = false, popup = false, trigger }: Props) {
  const theme = useTheme();
  const calendarConfig = calendar === 'jalali' ? persian : calendar === 'islamic' ? arabic : undefined;
  const locale = calendar === 'jalali' ? persian_fa : calendar === 'islamic' ? arabic_ar : undefined;
  const pickerProps = {
    value: value ?? new Date(), calendar: calendarConfig, locale,
    months: calendar === 'jalali' ? AFGHAN_MONTHS : undefined,
    plugins: showTime ? [<TimePicker position="bottom" hideSeconds />] : undefined,
    className: theme.palette.mode === 'dark' ? 'bg-dark' : undefined,
    onChange: (selected: any) => {
      if (!selected || Array.isArray(selected)) return;
      const date = selected.toDate();
      if (date instanceof Date && !Number.isNaN(date.getTime())) onSelect(date);
    },
  };
  if (popup) return <DatePicker {...pickerProps} render={(_value, open) => trigger?.(open) ?? null} />;
  return (
    <Calendar
      {...pickerProps}
    />
  );
}
