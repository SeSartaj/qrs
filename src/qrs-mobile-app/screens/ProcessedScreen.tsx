/**
 * Result screen for non-SDoc processing outcomes: an imported certificate, an
 * applied statement (attestation / revocation / block), or a processed bundle.
 */
import React from 'react';
import { ScrollView, StyleSheet, View } from 'react-native';
import { Appbar, Button, Card, Icon, List, Text, useTheme } from 'react-native-paper';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import type { RootStackParamList } from '../navigation/types';
import type { ProcessOutcome } from '../lib/process';
import { VerifiedBadge } from '../components/VerifiedBadge';

type Props = NativeStackScreenProps<RootStackParamList, 'Processed'>;

function shortId(id: string): string {
  return id.length > 22 ? `${id.slice(0, 11)}…${id.slice(-8)}` : id;
}

export function ProcessedScreen({ route, navigation }: Props) {
  const theme = useTheme();
  const { outcome } = route.params;

  const title =
    outcome.kind === 'tcert-imported'
      ? 'Certificate imported'
      : outcome.kind === 'statement'
        ? 'Statement processed'
        : 'Bundle processed';

  const ok =
    outcome.kind === 'tcert-imported' ||
    (outcome.kind === 'statement' && outcome.applied) ||
    (outcome.kind === 'bundle' && outcome.items.length > 0 && outcome.items.every((i) => i.ok));

  return (
    <View style={styles.root}>
      <Appbar.Header>
        <Appbar.BackAction onPress={() => navigation.goBack()} />
        <Appbar.Content title="Result" />
      </Appbar.Header>

      <ScrollView contentContainerStyle={styles.content}>
        <View style={[styles.banner, { backgroundColor: ok ? '#1E8E3E' : '#E37400' }]}>
          <Icon source={ok ? 'check-circle' : 'alert'} size={40} color="#fff" />
          <Text variant="titleLarge" style={styles.bannerText}>
            {title}
          </Text>
        </View>

        {outcome.kind === 'tcert-imported' && (
          <Card style={styles.card}>
            <Card.Content>
              <View style={styles.row}>
                <Text variant="titleLarge">{outcome.documentName ?? 'Certificate'}</Text>
                <VerifiedBadge />
              </View>
              <Text variant="bodyMedium" style={{ color: theme.colors.onSurfaceVariant }}>
                {outcome.issuerName ?? 'Unknown issuer'} · {shortId(outcome.tcertId)}
              </Text>
              <Text variant="bodySmall" style={{ color: theme.colors.onSurfaceVariant, marginTop: 6 }}>
                The certificate is now stored. You can pin it or add it as a CA from the Trust tab (admin password
                required).
              </Text>
            </Card.Content>
          </Card>
        )}

        {outcome.kind === 'statement' && (
          <Card style={styles.card}>
            <Card.Content>
              <List.Item
                title="Action"
                description={outcome.action}
                left={() => <List.Icon icon="gesture-tap" />}
              />
              <List.Item
                title="Status"
                description={outcome.applied ? 'Applied successfully' : (outcome.reason ?? 'Not applied')}
                left={() => <List.Icon icon={outcome.applied ? 'check' : 'close'} />}
              />
              {outcome.statementId ? (
                <Text variant="bodySmall" style={{ color: theme.colors.onSurfaceVariant }}>
                  Statement {shortId(outcome.statementId)}
                </Text>
              ) : null}
            </Card.Content>
          </Card>
        )}

        {outcome.kind === 'bundle' && (
          <Card style={styles.card}>
            <Card.Title title={`Processed ${outcome.items.length} object(s)`} />
            <Card.Content>
              {outcome.items.map((item, i) => (
                <List.Item
                  key={`${item.type}-${i}`}
                  title={item.type}
                  description={item.detail ?? (item.ok ? 'OK' : 'Failed')}
                  left={() => <List.Icon icon={item.ok ? 'check-circle' : 'alert-circle'} color={item.ok ? '#1E8E3E' : '#D93025'} />}
                />
              ))}
              {outcome.items.some((i) => i.type === 'statement' && i.ok) ? (
                <Text variant="bodySmall" style={{ color: theme.colors.onSurfaceVariant, marginTop: 6 }}>
                  A CA attestation with its full certificate was received. The certificate is now trusted via the CA.
                </Text>
              ) : null}
            </Card.Content>
          </Card>
        )}

        <Button mode="outlined" style={{ marginTop: 8 }} onPress={() => navigation.goBack()}>
          Done
        </Button>
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1 },
  content: { padding: 16, paddingBottom: 40 },
  banner: { borderRadius: 16, padding: 20, alignItems: 'center', marginBottom: 12 },
  bannerText: { color: '#fff', fontWeight: '700', marginTop: 4 },
  card: { marginBottom: 12 },
  row: { flexDirection: 'row', alignItems: 'center' },
});
