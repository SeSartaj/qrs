/**
 * Change admin password. On first launch (no password set yet) this screen
 * presents the "set password" form instead; afterwards it requires the current
 * password before allowing a change.
 */
import React, { useEffect, useState } from 'react';
import { ScrollView, StyleSheet, View } from 'react-native';
import { Appbar, Button, Card, Text, TextInput, useTheme } from 'react-native-paper';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import type { RootStackParamList } from '../navigation/types';
import { hasAdminPassword, setAdminPassword, verifyAdminPassword } from '../lib/password';

type Props = NativeStackScreenProps<RootStackParamList, 'ChangePassword'>;

export function ChangePasswordScreen({ navigation }: Props) {
  const theme = useTheme();
  const [configured, setConfigured] = useState<boolean | null>(null);

  // Set-password (first launch)
  const [pw, setPw] = useState('');
  const [pw2, setPw2] = useState('');
  // Change-password
  const [cur, setCur] = useState('');
  const [npw, setNpw] = useState('');
  const [npw2, setNpw2] = useState('');

  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  useEffect(() => {
    void (async () => setConfigured(await hasAdminPassword()))();
  }, []);

  const save = async (): Promise<void> => {
    setError(null);
    setDone(false);
    if (configured) {
      // Changing the password must never be authorized by the cached trust
      // action window; the entered current password must match the hash now.
      if (!(await verifyAdminPassword(cur, { requireFresh: true }))) {
        setError('Current password is incorrect.');
        return;
      }
      if (npw.length < 4) {
        setError('New password must be at least 4 characters.');
        return;
      }
      if (npw !== npw2) {
        setError('New passwords do not match.');
        return;
      }
    } else {
      if (pw.length < 4) {
        setError('Password must be at least 4 characters.');
        return;
      }
      if (pw !== pw2) {
        setError('Passwords do not match.');
        return;
      }
    }
    setBusy(true);
    await setAdminPassword(configured ? npw : pw);
    setBusy(false);
    setDone(true);
    setConfigured(true);
  };

  return (
    <View style={styles.root}>
      <Appbar.Header>
        <Appbar.BackAction onPress={() => navigation.goBack()} />
        <Appbar.Content title={configured ? 'Change password' : 'Set admin password'} />
      </Appbar.Header>

      <ScrollView contentContainerStyle={styles.content}>
        <Card style={styles.card}>
          <Card.Content>
            <Text variant="bodyMedium" style={{ marginBottom: 12 }}>
              {configured
                ? 'Enter your current password, then choose a new one. This password gates trust actions (pin, add CA, distrust).'
                : 'Set an admin password — it will be required to pin a certificate or add a CA.'}
            </Text>

            {configured ? (
              <>
                <TextInput
                  mode="outlined"
                  label="Current password"
                  secureTextEntry
                  value={cur}
                  onChangeText={setCur}
                  style={styles.field}
                />
                <TextInput
                  mode="outlined"
                  label="New password"
                  secureTextEntry
                  value={npw}
                  onChangeText={setNpw}
                  style={styles.field}
                />
                <TextInput
                  mode="outlined"
                  label="Confirm new password"
                  secureTextEntry
                  value={npw2}
                  onChangeText={setNpw2}
                  style={styles.field}
                />
              </>
            ) : (
              <>
                <TextInput
                  mode="outlined"
                  label="Password"
                  secureTextEntry
                  value={pw}
                  onChangeText={setPw}
                  style={styles.field}
                />
                <TextInput
                  mode="outlined"
                  label="Confirm password"
                  secureTextEntry
                  value={pw2}
                  onChangeText={setPw2}
                  style={styles.field}
                />
              </>
            )}

            {error ? <Text style={{ color: theme.colors.error, marginBottom: 8 }}>{error}</Text> : null}
            {done ? (
              <Text style={{ color: theme.colors.primary, marginBottom: 8 }}>Password saved.</Text>
            ) : null}

            <Button mode="contained" onPress={() => void save()} loading={busy} disabled={busy}>
              {configured ? 'Change password' : 'Save password'}
            </Button>
          </Card.Content>
        </Card>
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1 },
  content: { padding: 16, paddingBottom: 40 },
  card: { marginBottom: 12 },
  field: { marginBottom: 8 },
});
