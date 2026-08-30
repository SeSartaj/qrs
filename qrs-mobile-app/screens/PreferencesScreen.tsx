/**
 * Preferences: language + date format configuration.
 */
import React, { useCallback, useState } from 'react';
import { ScrollView, StyleSheet, View } from 'react-native';
import { useFocusEffect } from '@react-navigation/native';
import { Appbar, Divider, List, RadioButton, Switch, Text, useTheme } from 'react-native-paper';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';
import type { RootStackParamList } from '../navigation/types';
import {
  DATE_FORMATS,
  LANGUAGES,
  getSettings,
  setSettings,
  type AppSettings,
  type DateFormat,
  type LanguageCode,
} from '../lib/settings';
import { verifyAdminPassword } from '../lib/password';
import { PasswordDialog } from '../components/PasswordDialog';

type Nav = NativeStackNavigationProp<RootStackParamList, 'Preferences'>;

export function PreferencesScreen({ navigation }: { navigation: Nav }) {
  const theme = useTheme();
  const [settings, setSettingsState] = useState<AppSettings>({ language: 'en', dateFormat: 'gregorian', trustPolicy: 'any', historyEnabled: true });
  const [pendingHistory, setPendingHistory] = useState<boolean | null>(null);

  useFocusEffect(
    useCallback(() => {
      void (async () => {
        setSettingsState(await getSettings());
      })();
    }, [])
  );

  const update = (patch: Partial<AppSettings>): void => {
    const next = { ...settings, ...patch };
    setSettingsState(next);
    void setSettings(next);
  };

  const selectHistory = (enabled: boolean): void => {
    if (enabled === settings.historyEnabled) return;
    setPendingHistory(enabled);
  };

  const confirmHistory = async (password: string): Promise<boolean> => {
    const ok = await verifyAdminPassword(password);
    if (ok && pendingHistory !== null) {
      update({ historyEnabled: pendingHistory });
      setPendingHistory(null);
    }
    return ok;
  };

  return (
    <View style={styles.root}>
      <Appbar.Header>
        <Appbar.BackAction onPress={() => navigation.goBack()} />
        <Appbar.Content title="Preferences" />
      </Appbar.Header>

      <ScrollView contentContainerStyle={styles.content}>
        <List.Section>
          <List.Subheader style={styles.sectionLabel}>LANGUAGE</List.Subheader>
          {LANGUAGES.map((lang) => (
            <List.Item
              key={lang.code}
              title={lang.label}
              onPress={() => update({ language: lang.code as LanguageCode })}
              right={() => (
                <RadioButton
                  value={lang.code}
                  status={settings.language === lang.code ? 'checked' : 'unchecked'}
                  onPress={() => update({ language: lang.code as LanguageCode })}
                />
              )}
            />
          ))}
          <Divider />
        </List.Section>

        <List.Section>
          <List.Subheader style={styles.sectionLabel}>DATE FORMAT</List.Subheader>
          {DATE_FORMATS.map((fmt) => (
            <List.Item
              key={fmt.code}
              title={fmt.label}
              onPress={() => update({ dateFormat: fmt.code as DateFormat })}
              right={() => (
                <RadioButton
                  value={fmt.code}
                  status={settings.dateFormat === fmt.code ? 'checked' : 'unchecked'}
                  onPress={() => update({ dateFormat: fmt.code as DateFormat })}
                />
              )}
            />
          ))}
          <Divider />
        </List.Section>

        <List.Section>
          <List.Subheader style={styles.sectionLabel}>HISTORY</List.Subheader>
          <List.Item
            title="Record processed items"
            description="Store scanned documents and TCerts in local history"
            left={(props) => <List.Icon {...props} icon="history" />}
            right={() => <Switch value={settings.historyEnabled} onValueChange={selectHistory} />}
          />
          <Divider />
        </List.Section>

        <Text variant="bodySmall" style={[styles.hint, { color: theme.colors.onSurfaceVariant }]}>
          Language and date format are stored locally on this device.
        </Text>
      </ScrollView>
      <PasswordDialog
        visible={pendingHistory !== null}
        title="Change history setting"
        message="Enter the admin password to change local history recording."
        onCancel={() => setPendingHistory(null)}
        onConfirm={confirmHistory}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1 },
  content: { paddingBottom: 40 },
  sectionLabel: { color: '#6A7280', fontSize: 12, letterSpacing: 0.6 },
  hint: { textAlign: 'center', marginTop: 16, paddingHorizontal: 24 },
});
