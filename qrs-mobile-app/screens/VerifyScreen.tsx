/**
 * Verify / Process tab: paste a payload (document, certificate, statement or
 * bundle) and it is handled intelligently. QR scanning lives in the Scan tab.
 */
import React, { useCallback, useState } from 'react';
import { ScrollView, StyleSheet, View } from 'react-native';
import {
  Appbar,
  Button,
  Card,
  Chip,
  Divider,
  List,
  Text,
  TextInput,
  useTheme,
} from 'react-native-paper';
import { useFocusEffect } from '@react-navigation/native';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';
import type { RootStackParamList } from '../navigation/types';
import { addHistory, historyVerdictColor, loadHistory, type HistoryEntry } from '../lib/history';
import { pickQrsFile } from '../lib/fileImport';
import { processPayload } from '../lib/process';
import { formatMs, getSettings, type DateFormat } from '../lib/settings';

type Nav = NativeStackNavigationProp<RootStackParamList, 'Tabs'>;

export function VerifyScreen({ navigation }: { navigation: Nav }) {
  const theme = useTheme();
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
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

  const runVerify = async (raw: string): Promise<void> => {
    setError(null);
    setBusy(true);
    try {
      const outcome = await processPayload(raw);
      if (outcome.kind === 'verified') {
        await addHistory({
          raw,
          documentName: outcome.result.documentName,
          issuerName: outcome.result.issuerName,
          verdict: outcome.result.verdict,
          ts: Date.now(),
        });
        await refresh();
        navigation.navigate('Result', { result: outcome.result });
      } else {
        navigation.navigate('Processed', { outcome });
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not process the input.');
    } finally {
      setBusy(false);
    }
  };

  const importFile = async (): Promise<void> => {
    if (busy) return;
    const res = await pickQrsFile();
    if (res.canceled) return;
    if (res.error || !res.file) {
      setError(res.error ?? 'Could not read the selected file.');
      return;
    }
    setInput(res.file.text);
    await runVerify(res.file.text);
  };

  return (
    <View style={styles.root}>
      <Appbar.Header>
        <Appbar.Content title="Process" />
      </Appbar.Header>

      <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
        <Card style={styles.card}>
          <Card.Title title="Process" subtitle="Paste or scan a document, certificate, statement or bundle" />
          <Card.Content>
            <TextInput
              mode="outlined"
              label="Payload (base64url or qrs://…)"
              multiline
              numberOfLines={4}
              value={input}
              onChangeText={setInput}
              style={styles.input}
              autoCapitalize="none"
              autoCorrect={false}
            />
            {error ? <Text style={[styles.error, { color: theme.colors.error }]}>{error}</Text> : null}
            <View style={styles.actions}>
              <Button
                mode="contained"
                loading={busy}
                disabled={busy || !input.trim()}
                onPress={() => void runVerify(input)}
                icon="shield-check"
              >
                Process
              </Button>
              <Button
                mode="outlined"
                icon="file-upload"
                disabled={busy}
                onPress={() => void importFile()}
              >
                Import .qrs file
              </Button>
            </View>
          </Card.Content>
        </Card>

        {history.length > 0 && (
          <>
            <Divider style={{ marginVertical: 8 }} />
            <Text variant="titleSmall">Recently verified</Text>
            {history.map((h, i) => (
              <List.Item
                key={`${h.ts}-${i}`}
                title={h.documentName ?? 'Document'}
                description={`${h.issuerName ?? 'Unknown issuer'} · ${formatMs(h.ts, dateFormat)}`}
                left={() => (
                  <Chip
                    mode="outlined"
                    textStyle={{ fontSize: 10, color: historyVerdictColor(h.verdict) }}
                    style={[styles.verdictChip, { borderColor: historyVerdictColor(h.verdict) }]}
                  >
                    {h.verdict.toUpperCase()}
                  </Chip>
                )}
                onPress={() => {
                  void runVerify(h.raw);
                }}
              />
            ))}
          </>
        )}
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1 },
  content: { padding: 16, paddingBottom: 40 },
  card: { marginBottom: 12 },
  input: { marginBottom: 8 },
  actions: { flexDirection: 'row', gap: 8, marginTop: 4, flexWrap: 'wrap' },
  error: { marginBottom: 4 },
  verdictChip: { alignSelf: 'center' },
});
