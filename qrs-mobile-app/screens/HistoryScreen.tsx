/**
 * History tab: every previously processed payload (documents, certificates,
 * statements and bundles), newest first. Tapping an entry re-processes it so you
 * can jump back to its result. A clear action empties the list.
 */
import React, { useCallback, useState } from 'react';
import { FlatList, StyleSheet, View } from 'react-native';
import { useFocusEffect } from '@react-navigation/native';
import { Appbar, Chip, Icon, List, Text, useTheme } from 'react-native-paper';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';
import type { RootStackParamList } from '../navigation/types';
import { clearHistory, historyVerdictColor, loadHistory, type HistoryEntry } from '../lib/history';
import { processPayload } from '../lib/process';
import { formatMs, getSettings, type DateFormat } from '../lib/settings';

type Nav = NativeStackNavigationProp<RootStackParamList, 'Tabs'>;

export function HistoryScreen({ navigation }: { navigation: Nav }) {
  const theme = useTheme();
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const [dateFormat, setDateFormat] = useState<DateFormat>('gregorian');

  const refresh = useCallback(async () => {
    setHistory(await loadHistory());
    setDateFormat((await getSettings()).dateFormat);
  }, []);

  useFocusEffect(
    useCallback(() => {
      void refresh();
    }, [refresh])
  );

  const reprocess = async (h: HistoryEntry): Promise<void> => {
    if (busy) return;
    setBusy(true);
    try {
      const outcome = await processPayload(h.raw);
      if (outcome.kind === 'verified') navigation.navigate('Result', { result: outcome.result });
      else navigation.navigate('Processed', { outcome });
    } catch {
      /* ignore re-process errors */
    } finally {
      setBusy(false);
    }
  };

  const onClear = async (): Promise<void> => {
    await clearHistory();
    await refresh();
  };

  return (
    <View style={styles.root}>
      <Appbar.Header>
        <Appbar.Content title="History" />
        {history.length > 0 ? <Appbar.Action icon="delete-sweep-outline" onPress={() => void onClear()} /> : null}
      </Appbar.Header>

      {history.length === 0 ? (
        <View style={styles.empty}>
          <Icon source="history" size={44} color={theme.colors.onSurfaceVariant} />
          <Text variant="bodyLarge" style={{ marginTop: 10 }}>
            No history yet
          </Text>
          <Text variant="bodySmall" style={{ color: theme.colors.onSurfaceVariant, textAlign: 'center', marginTop: 4 }}>
            Documents, certificates and statements you process will appear here.
          </Text>
        </View>
      ) : (
        <FlatList
          data={history}
          keyExtractor={(h, i) => `${h.ts}-${i}`}
          contentContainerStyle={styles.list}
          ItemSeparatorComponent={() => <View style={styles.sep} />}
          renderItem={({ item }) => {
            const c = historyVerdictColor(item.verdict);
            return (
              <List.Item
                title={item.documentName ?? 'Document'}
                description={`${item.issuerName ?? 'Unknown issuer'} · ${formatMs(item.ts, dateFormat)}`}
                left={() => (
                  <Chip
                    mode="outlined"
                    textStyle={{ fontSize: 10, color: c }}
                    style={[styles.verdictChip, { borderColor: c }]}
                  >
                    {item.verdict.toUpperCase()}
                  </Chip>
                )}
                onPress={() => void reprocess(item)}
              />
            );
          }}
        />
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1 },
  list: { padding: 8, paddingBottom: 24 },
  sep: { height: 1, backgroundColor: 'rgba(128,128,128,0.2)', marginLeft: 16 },
  verdictChip: { alignSelf: 'center' },
  empty: { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 24 },
});
