/**
 * Settings: a list of admin pages. Each row opens a dedicated screen:
 *  - Change / set admin password → ChangePassword
 *  - Clear all data → Data
 */
import React, { useCallback, useState } from 'react';
import { Alert, ScrollView, StyleSheet, View } from 'react-native';
import { useFocusEffect } from '@react-navigation/native';
import { Appbar, Divider, List, Text, useTheme } from 'react-native-paper';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';
import type { RootStackParamList } from '../navigation/types';
import { hasAdminPassword } from '../lib/password';
import {
  DetailsFormBottomSheet,
  type DetailsFormBottomSheetHandle,
  type DetailsFormValues,
} from '../components/DetailsFormBottomSheet';

type Nav = NativeStackNavigationProp<RootStackParamList, 'Tabs'>;

export function SettingsScreen({ navigation }: { navigation: Nav }) {
  const theme = useTheme();
  const [configured, setConfigured] = useState(false);
  const formRef = React.useRef<DetailsFormBottomSheetHandle>(null);

  const refresh = useCallback(async () => {
    setConfigured(await hasAdminPassword());
  }, []);

  useFocusEffect(
    useCallback(() => {
      void refresh();
    }, [refresh])
  );

  const submitDetails = useCallback(async ({ title }: DetailsFormValues) => {
    // Replace this demo acknowledgement with the app's persistence/API call.
    Alert.alert('Submitted', title);
  }, []);

  return (
    <View style={styles.root}>
      <Appbar.Header>
        <Appbar.Content title="Settings" />
      </Appbar.Header>

      <ScrollView contentContainerStyle={styles.content}>
        <List.Section>
          <List.Subheader style={styles.sectionLabel}>BOTTOM SHEET EXAMPLE</List.Subheader>
          <List.Item
            title="Open details form"
            description="Keyboard-aware modal above the tab bar"
            left={(props) => <List.Icon {...props} icon="form-textbox" />}
            right={(props) => <List.Icon {...props} icon="chevron-up" />}
            onPress={() => formRef.current?.present()}
          />
          <Divider />
        </List.Section>

        <List.Section>
          <List.Subheader style={styles.sectionLabel}>SECURITY</List.Subheader>
          <List.Item
            title={configured ? 'Change password' : 'Set admin password'}
            description={
              configured ? 'Gates trust actions (pin, add CA, distrust)' : 'Required before trust actions'
            }
            left={(props) => <List.Icon {...props} icon="lock-outline" />}
            right={(props) => <List.Icon {...props} icon="chevron-right" />}
            onPress={() => navigation.navigate('ChangePassword')}
          />
          <Divider />
        </List.Section>

        <List.Section>
          <List.Subheader style={styles.sectionLabel}>PREFERENCES</List.Subheader>
          <List.Item
            title="Language & date format"
            description="Choose UI language and how dates are shown"
            left={(props) => <List.Icon {...props} icon="translate" />}
            right={(props) => <List.Icon {...props} icon="chevron-right" />}
            onPress={() => navigation.navigate('Preferences')}
          />
          <Divider />
          <List.Item
            title="Trust policy"
            description="How trust is resolved when multiple CAs attest a certificate"
            left={(props) => <List.Icon {...props} icon="shield-account" />}
            right={(props) => <List.Icon {...props} icon="chevron-right" />}
            onPress={() => navigation.navigate('TrustPolicy')}
          />
          <Divider />
        </List.Section>

        <List.Section>
          <List.Subheader style={styles.sectionLabel}>DATA</List.Subheader>
          <List.Item
            title="Clear all data"
            description="Remove certificates, documents, trust and history"
            left={(props) => <List.Icon {...props} icon="delete-outline" color={theme.colors.error} />}
            right={(props) => <List.Icon {...props} icon="chevron-right" />}
            onPress={() => navigation.navigate('Data')}
          />
          <Divider />
        </List.Section>

        <Text variant="bodySmall" style={[styles.version, { color: theme.colors.onSurfaceVariant }]}>
          QRS Verifier · 1.0.0
        </Text>
      </ScrollView>
      <DetailsFormBottomSheet ref={formRef} onSubmit={submitDetails} />
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1 },
  content: { paddingBottom: 40 },
  sectionLabel: { color: '#6A7280', fontSize: 12, letterSpacing: 0.6 },
  version: { textAlign: 'center', marginTop: 16 },
});
