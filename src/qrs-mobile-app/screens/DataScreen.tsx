/**
 * Data: see what is stored on this device and clear all app data
 * (certificates, documents, trust, revocation, history and the admin password).
 */
import React, { useCallback, useState } from 'react';
import { ScrollView, StyleSheet, View } from 'react-native';
import { useFocusEffect } from '@react-navigation/native';
import { Appbar, Button, Card, Dialog, Portal, Text, useTheme } from 'react-native-paper';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import AsyncStorage from '@react-native-async-storage/async-storage';
import type { RootStackParamList } from '../navigation/types';
import { clearAdminPassword } from '../lib/password';

type Props = NativeStackScreenProps<RootStackParamList, 'Data'>;

export function DataScreen({ navigation }: Props) {
  const theme = useTheme();
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [confirm, setConfirm] = useState(false);
  const [cleared, setCleared] = useState(false);

  const refresh = useCallback(async () => {
    const entries: Record<string, number> = {};
    for (const name of ['certificates', 'documents', 'revocation', 'trust']) {
      const raw = await AsyncStorage.getItem(`qrs.${name}`);
      try {
        const arr = raw ? (JSON.parse(raw) as unknown[]) : [];
        entries[name] = Array.isArray(arr) ? arr.length : 1;
      } catch {
        entries[name] = 0;
      }
    }
    setCounts(entries);
  }, []);

  useFocusEffect(
    useCallback(() => {
      void refresh();
    }, [refresh])
  );

  const doClear = async (): Promise<void> => {
    setConfirm(false);
    await clearAdminPassword();
    const keys = await AsyncStorage.getAllKeys();
    await AsyncStorage.multiRemove(keys.filter((k) => k.startsWith('qrs.')));
    setCleared(true);
    await refresh();
  };

  return (
    <View style={styles.root}>
      <Appbar.Header>
        <Appbar.BackAction onPress={() => navigation.goBack()} />
        <Appbar.Content title="Data" />
      </Appbar.Header>

      <ScrollView contentContainerStyle={styles.content}>
        <Card style={styles.card}>
          <Card.Title title="Stored on this device" titleVariant="titleMedium" />
          <Card.Content>
            {Object.keys(counts).length === 0 ? (
              <Text variant="bodyMedium" style={{ color: theme.colors.onSurfaceVariant }}>
                Loading…
              </Text>
            ) : (
              Object.entries(counts).map(([k, v]) => (
                <View key={k} style={styles.row}>
                  <Text variant="bodyMedium" style={styles.rowLabel}>
                    {k}
                  </Text>
                  <Text variant="bodyMedium" style={styles.rowValue}>
                    {v}
                  </Text>
                </View>
              ))
            )}
            <Text variant="bodySmall" style={{ color: theme.colors.onSurfaceVariant, marginTop: 12 }}>
              Clearing removes all certificates, documents, trust decisions, revocation lists, verification
              history and the admin password from this device.
            </Text>
          </Card.Content>
        </Card>

        {cleared ? (
          <Text variant="bodyMedium" style={{ color: theme.colors.primary, textAlign: 'center', marginVertical: 12 }}>
            All data cleared.
          </Text>
        ) : null}

        <Button
          mode="outlined"
          textColor={theme.colors.error}
          style={styles.clearBtn}
          onPress={() => setConfirm(true)}
        >
          Clear all data
        </Button>
      </ScrollView>

      <Portal>
        <Dialog visible={confirm} onDismiss={() => setConfirm(false)}>
          <Dialog.Title>Clear all data?</Dialog.Title>
          <Dialog.Content>
            <Text variant="bodyMedium">
              This permanently deletes everything stored on this device, including the admin password. This
              cannot be undone.
            </Text>
          </Dialog.Content>
          <Dialog.Actions>
            <Button onPress={() => setConfirm(false)}>Cancel</Button>
            <Button textColor={theme.colors.error} onPress={() => void doClear()}>
              Clear
            </Button>
          </Dialog.Actions>
        </Dialog>
      </Portal>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1 },
  content: { padding: 16, paddingBottom: 40 },
  card: { marginBottom: 12 },
  row: { flexDirection: 'row', justifyContent: 'space-between', paddingVertical: 4 },
  rowLabel: { color: '#6A7280' },
  rowValue: { fontWeight: '600' },
  clearBtn: { marginTop: 8 },
});
