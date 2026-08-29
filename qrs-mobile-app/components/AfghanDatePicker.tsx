import { useMemo, useState } from 'react';
import { Modal, StyleSheet, View } from 'react-native';
import { Button, IconButton, Surface, Text } from 'react-native-paper';
import { convertDateParts, formatDate, type Calendar } from 'tri-calendar';

interface Props {
  value?: Date;
  calendar: Calendar;
  onSelect: (date: Date) => void;
}

const WEEKDAYS = ['Sa', 'Su', 'Mo', 'Tu', 'We', 'Th', 'Fr'];

/** Calendar month grid using tri-calendar's Dari/Jalali conversion. */
export function AfghanDatePicker({ value, calendar, onSelect }: Props) {
  const selectedValue = value ?? new Date();
  const [anchor, setAnchor] = useState(() => new Date(selectedValue.getFullYear(), selectedValue.getMonth(), 1));
  const parts = useMemo(() => convertDateParts(anchor, 'gregorian', calendar), [anchor, calendar]);
  const cells = useMemo(() => {
    const firstParts = convertDateParts({ year: parts.year, month: parts.month, day: 1 }, calendar, 'gregorian');
    const first = new Date(firstParts.year, firstParts.month - 1, firstParts.day);
    const days: Date[] = [];
    for (let i = 0; i < 32; i++) {
      const date = new Date(first.getFullYear(), first.getMonth(), first.getDate() + i);
      const current = convertDateParts(date, 'gregorian', calendar);
      if (current.year !== parts.year || current.month !== parts.month) break;
      days.push(date);
    }
    return [...Array((first.getDay() + 1) % 7).fill(null), ...days] as (Date | null)[];
  }, [parts, calendar]);
  const shift = (delta: number): void => {
    const targetMonth = parts.month + delta;
    const year = targetMonth < 1 ? parts.year - 1 : targetMonth > 12 ? parts.year + 1 : parts.year;
    const month = targetMonth < 1 ? 12 : targetMonth > 12 ? 1 : targetMonth;
    const next = convertDateParts({ year, month, day: 1 }, calendar, 'gregorian');
    setAnchor(new Date(next.year, next.month - 1, next.day));
  };
  const locale = calendar === 'gregorian' ? 'en' : 'prs';
  return (
    <Surface style={styles.surface} elevation={2}>
      <View style={styles.header}>
        <IconButton icon="chevron-left" onPress={() => shift(-1)} />
        <Text variant="titleSmall">{formatDate(parts, calendar, 'MMMM YYYY', locale, 'latn')}</Text>
        <IconButton icon="chevron-right" onPress={() => shift(1)} />
      </View>
      <View style={styles.grid}>{WEEKDAYS.map((day) => <Text key={day} style={styles.weekday}>{day}</Text>)}</View>
      <View style={styles.grid}>
        {cells.map((date, index) => date ? (
          <Button
            key={date.toISOString()}
            compact
            mode={date.toDateString() === selectedValue.toDateString() ? 'contained' : 'text'}
            onPress={() => onSelect(date)}
            style={styles.day}
          >
            {formatDate(convertDateParts(date, 'gregorian', calendar), calendar, 'D', locale, 'latn')}
          </Button>
        ) : <View key={`empty-${index}`} style={styles.day} />)}
      </View>
    </Surface>
  );
}

export function AfghanDatePickerModal({ visible, onDismiss, ...props }: Props & { visible: boolean; onDismiss: () => void }) {
  return <Modal visible={visible} transparent animationType="fade" onRequestClose={onDismiss}><View style={styles.modal}><AfghanDatePicker {...props} /></View></Modal>;
}

const styles = StyleSheet.create({
  modal: { flex: 1, justifyContent: 'center', alignItems: 'center', backgroundColor: 'rgba(0,0,0,0.45)' },
  surface: { width: 320, padding: 8, borderRadius: 12 },
  header: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' },
  grid: { flexDirection: 'row', flexWrap: 'wrap' },
  weekday: { width: '14.285%', textAlign: 'center', opacity: 0.65, paddingVertical: 6 },
  day: { width: '14.285%', minWidth: '14.285%', marginHorizontal: 0, paddingHorizontal: 0 },
});