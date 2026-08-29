/**
 * Trust policy: how the app resolves trust when a TCert is attested by multiple
 * CAs. Changing the policy is a trust-affecting action, so it is gated behind
 * the admin password (like pin / add CA / distrust).
 *
 *   Any trusted CA  → valid if at least one trusted CA attests the TCert.
 *   All trusted CAs → untrusted if any CA that attested the TCert no longer
 *                     trusts it (e.g. one CA revoked it).
 */
import React, { useCallback, useState } from 'react';
import { ScrollView, StyleSheet, View } from 'react-native';
import { useFocusEffect } from '@react-navigation/native';
import { Appbar, Divider, List, RadioButton, Text, useTheme } from 'react-native-paper';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';
import type { RootStackParamList } from '../navigation/types';
import { getSettings, setSettings, TRUST_POLICIES, type AppSettings, type TrustPolicy } from '../lib/settings';
import { verifyAdminPassword } from '../lib/password';
import { PasswordDialog } from '../components/PasswordDialog';

type Nav = NativeStackNavigationProp<RootStackParamList, 'TrustPolicy'>;

export function TrustPolicyScreen({ navigation }: { navigation: Nav }) {
  const theme = useTheme();
  const [policy, setPolicy] = useState<TrustPolicy>('any');
  const [pending, setPending] = useState<TrustPolicy | null>(null);

  useFocusEffect(
    useCallback(() => {
      void (async () => {
        setPolicy((await getSettings()).trustPolicy);
      })();
    }, [])
  );

  const apply = async (next: TrustPolicy): Promise<void> => {
    const settings: AppSettings = { ...(await getSettings()), trustPolicy: next };
    await setSettings(settings);
    setPolicy(next);
  };

  const select = (next: TrustPolicy): void => {
    if (next === policy) return;
    // Trust-affecting change → require the admin password.
    setPending(next);
  };

  const confirmPassword = async (password: string): Promise<boolean> => {
    const ok = await verifyAdminPassword(password);
    if (ok && pending) {
      await apply(pending);
      setPending(null);
    }
    return ok;
  };

  return (
    <View style={styles.root}>
      <Appbar.Header>
        <Appbar.BackAction onPress={() => navigation.goBack()} />
        <Appbar.Content title="Trust policy" />
      </Appbar.Header>

      <ScrollView contentContainerStyle={styles.content}>
        <Text variant="bodyMedium" style={[styles.intro, { color: theme.colors.onSurfaceVariant }]}>
          When two or more CAs attest the same certificate, choose how trust is resolved.
        </Text>

        <List.Section>
          {TRUST_POLICIES.map((opt) => (
            <List.Item
              key={opt.code}
              title={opt.label}
              description={opt.description}
              onPress={() => select(opt.code)}
              right={() => (
                <RadioButton
                  value={opt.code}
                  status={policy === opt.code ? 'checked' : 'unchecked'}
                  onPress={() => select(opt.code)}
                />
              )}
            />
          ))}
          <Divider />
        </List.Section>

        <Text variant="bodySmall" style={[styles.hint, { color: theme.colors.onSurfaceVariant }]}>
          Changing the trust policy requires the admin password.
        </Text>
      </ScrollView>

      <PasswordDialog
        visible={pending !== null}
        title="Change trust policy"
        message="Enter the admin password to apply this trust policy."
        onCancel={() => setPending(null)}
        onConfirm={confirmPassword}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1 },
  content: { paddingBottom: 40 },
  intro: { paddingHorizontal: 16, paddingTop: 12 },
  hint: { textAlign: 'center', marginTop: 16, paddingHorizontal: 24 },
});
