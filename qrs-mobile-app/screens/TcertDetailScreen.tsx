/**
 * TCert detail: shows a certificate's identity, trust state, distribution
 * endpoints and a "Sync" button that pulls the TCert + its statements from the
 * server(s) the certificate points to. Trust mutations stay on the Trust page.
 */
import React, { useCallback, useState } from 'react';
import { Alert, KeyboardAvoidingView, Platform, ScrollView, StyleSheet, View } from 'react-native';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import {
  Appbar,
  Button,
  Card,
  Chip,
  Dialog,
  Portal,
  SegmentedButtons,
  Text,
  TextInput,
  useTheme,
} from 'react-native-paper';
import { parseSignedObject, type QrsRuntime } from 'qrs-core';
import { getQrs } from '../lib/runtime';
import { syncEndpointsFor, syncCert, type MobileSyncResult } from '../lib/sync';
import { VerifiedBadge } from '../components/VerifiedBadge';
import { VERIFIED_BLUE } from '../lib/theme';
import { formatEpoch, getSettings, type DateFormat } from '../lib/settings';
import type { RootStackParamList } from '../navigation/types';

type Props = NativeStackScreenProps<RootStackParamList, 'TcertDetail'>;

interface CertDetail {
  tcertId: string;
  keyId: string;
  name: string;
  algorithm: string;
  validity?: { validAfter?: number; validBefore?: number; sdocMaxAgeSeconds?: number };
  pinned: boolean;
  isCa: boolean;
  distrusted: boolean;
  trusted: boolean;
  caName?: string;
  endpoints: string[];
  mirrors: string[];
  signedDefault?: string;
  statementGroups: Record<'attestations' | 'revocations' | 'sdocs', StatementRow[]>;
}

interface StatementRow { type: string; target: string; issuedAt: number; reason?: string }

function fmtEpoch(epoch: number | undefined, format: DateFormat): string {
  if (epoch === undefined) return '—';
  return formatEpoch(epoch, format);
}

function truncateName(name: string, max = 42): string {
  const value = name.trim() || 'Unknown';
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

async function loadDetail(qrs: QrsRuntime, tcertId: string): Promise<CertDetail | null> {
  const bytes = await qrs.deps.certificateStore.get(tcertId);
  if (!bytes) return null;
  let parsed;
  try {
    parsed = parseSignedObject(bytes);
  } catch {
    return null;
  }
  if (parsed.type !== 'tcert') return null;
  const data = parsed.data as unknown as {
    identity?: { name?: string };
    algorithm?: string;
    validity?: { validAfter?: number; validBefore?: number; sdocMaxAgeSeconds?: number };
    onlineEndpoint?: string;
  };
  const [pinned, isCa, distrusted, trust, attestations, revokedAttestations, revokedTcerts, revokedKeys, sdocStatements] = await Promise.all([
    qrs.deps.trustStore.isPinned(tcertId),
    qrs.deps.trustStore.isCa(tcertId),
    qrs.deps.trustStore.isDistrusted(tcertId),
    qrs.trust.resolveTrust(tcertId),
    qrs.deps.trustStore.listAttestations(),
    qrs.deps.revocationStore.listRevokedAttestation(),
    qrs.deps.revocationStore.listRevokedTcert(),
    qrs.deps.revocationStore.listRevokedKey(),
    qrs.deps.revocationStore.listSdocStatements(),
  ]);
  const signedByThis = (entry: { byTcertId?: string; byKeyId?: string }): boolean =>
    entry.byTcertId === tcertId || (!entry.byTcertId && entry.byKeyId === parsed.signerKeyId);
  const newestFirst = (rows: StatementRow[]): StatementRow[] => rows.sort((a, b) => b.issuedAt - a.issuedAt);
  const signedDefault = typeof data.onlineEndpoint === 'string'
    ? data.onlineEndpoint.trim().replace(/\/+$/, '')
    : undefined;
  const mirrors = (await qrs.endpoints.listMirrors(tcertId)).filter((ep) => ep !== signedDefault);
  return {
    tcertId,
    keyId: parsed.signerKeyId,
    name: data.identity?.name ?? 'Unknown',
    algorithm: data.algorithm ?? parsed.algorithm,
    validity: data.validity,
    pinned,
    isCa,
    distrusted,
    trusted: trust.state === 'valid',
    caName: trust.ca?.caName,
    endpoints: await qrs.endpoints.effectiveEndpoints(tcertId),
    mirrors,
    signedDefault,
    statementGroups: {
      attestations: newestFirst(attestations.filter((x) => x.caTcertId === tcertId).map((x) => ({ type: 'Attestation', target: x.targetTcertId, issuedAt: x.issuedAt }))),
      revocations: newestFirst([
        ...revokedAttestations.filter((x) => x.caTcertId === tcertId).map((x) => ({ type: 'Attestation revocation', target: x.targetTcertId, issuedAt: x.entry.issuedAt, reason: x.entry.reason })),
        ...revokedTcerts.filter((x) => signedByThis(x.entry)).map((x) => ({ type: `TCert revocation (${x.entry.type})`, target: x.tcertId, issuedAt: x.entry.issuedAt, reason: x.entry.reason })),
        ...revokedKeys.filter((x) => signedByThis(x.entry)).map((x) => ({ type: 'Key revocation', target: x.keyId, issuedAt: x.entry.issuedAt, reason: x.entry.reason })),
      ]),
      sdocs: newestFirst(sdocStatements.filter((x) => signedByThis(x.entry)).map((x) => ({ type: x.entry.action === 'blockSdoc' ? 'SDoc block' : 'SDoc unblock', target: x.sdocId, issuedAt: x.entry.issuedAt, reason: x.entry.reason }))),
    },
  };
}

export function TcertDetailScreen({ route, navigation }: Props) {
  const theme = useTheme();
  const { tcertId } = route.params;
  const qrs = getQrs();
  const [detail, setDetail] = useState<CertDetail | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [result, setResult] = useState<MobileSyncResult | null>(null);
  const [promptOpen, setPromptOpen] = useState(false);
  const [promptUrl, setPromptUrl] = useState('');
  const [endpointUrl, setEndpointUrl] = useState('');
  const [endpointBusy, setEndpointBusy] = useState(false);
  const [dateFormat, setDateFormat] = useState<DateFormat>('gregorian');
  const [tab, setTab] = useState<'overview' | 'attestations' | 'revocations' | 'sdocs'>('overview');

  const refresh = useCallback(async () => {
    setDetail(await loadDetail(qrs, tcertId));
    setDateFormat((await getSettings()).dateFormat);
  }, [qrs, tcertId]);

  React.useEffect(() => {
    void refresh();
  }, [refresh]);

  const doSync = async (endpoint?: string): Promise<void> => {
    if (syncing) return;
    const url = endpoint?.trim();
    if (!url && (await syncEndpointsFor(qrs, tcertId)).length === 0) {
      setPromptOpen(true);
      return;
    }
    setSyncing(true);
    setResult(null);
    const aggregate = url ? await syncCert(qrs, tcertId, { endpoint: url }) : await syncCert(qrs, tcertId);
    setResult(aggregate);
    setSyncing(false);
    await refresh();
    if (aggregate.errors.length > 0) {
      Alert.alert('Sync finished with errors', aggregate.errors.join('\n'));
    }
  };

  const addMirror = async (): Promise<void> => {
    const url = endpointUrl.trim();
    if (!url || endpointBusy) return;
    setEndpointBusy(true);
    try {
      await qrs.endpoints.addMirror(tcertId, url);
      setEndpointUrl('');
      await refresh();
    } catch (error) {
      Alert.alert('Unable to add endpoint', error instanceof Error ? error.message : String(error));
    } finally {
      setEndpointBusy(false);
    }
  };

  const removeMirror = async (url: string): Promise<void> => {
    if (endpointBusy) return;
    setEndpointBusy(true);
    try {
      await qrs.endpoints.removeMirror(tcertId, url);
      await refresh();
    } catch (error) {
      Alert.alert('Unable to remove endpoint', error instanceof Error ? error.message : String(error));
    } finally {
      setEndpointBusy(false);
    }
  };

  if (!detail) {
    return (
      <View style={styles.root}>
        <Appbar.Header>
          <Appbar.BackAction onPress={() => navigation.goBack()} />
          <Appbar.Content title="Certificate" />
        </Appbar.Header>
        <View style={styles.center}>
          <Text variant="bodyMedium">Certificate not found.</Text>
        </View>
      </View>
    );
  }

  const validityText =
    detail.validity?.validAfter !== undefined || detail.validity?.validBefore !== undefined
      ? `${fmtEpoch(detail.validity.validAfter, dateFormat)} → ${fmtEpoch(detail.validity.validBefore, dateFormat)}`
      : '—';

  return (
    <KeyboardAvoidingView
      style={styles.root}
      behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
      keyboardVerticalOffset={0}
    >
      <Appbar.Header>
        <Appbar.BackAction onPress={() => navigation.goBack()} />
        <Appbar.Content title={truncateName(detail.name)} />
      </Appbar.Header>

      <ScrollView
        contentContainerStyle={styles.content}
        keyboardShouldPersistTaps="handled"
        keyboardDismissMode={Platform.OS === 'ios' ? 'interactive' : 'on-drag'}
        automaticallyAdjustKeyboardInsets
      >
        <SegmentedButtons
          value={tab}
          onValueChange={(value) => setTab(value as typeof tab)}
          buttons={[
            { value: 'overview', label: 'Overview' },
            { value: 'attestations', label: `Attest (${detail.statementGroups.attestations.length})` },
            { value: 'revocations', label: `Revoke (${detail.statementGroups.revocations.length})` },
            { value: 'sdocs', label: `SDoc (${detail.statementGroups.sdocs.length})` },
          ]}
          style={styles.tabs}
        />
        {tab === 'overview' ? <>
        <Card style={styles.card} mode="outlined">
          <Card.Title
            title={<Text variant="titleMedium">{detail.name}</Text>}
            titleVariant="titleMedium"
            subtitle={detail.tcertId}
            right={() => (detail.pinned && !detail.caName ? <VerifiedBadge /> : null)}
          />
          <Card.Content>
            <Text variant="bodySmall" style={styles.muted}>
              ID
            </Text>
            <Text variant="bodyMedium" style={styles.mono}>
              {detail.tcertId}
            </Text>
            <View style={styles.rowChips}>
              <Chip textStyle={{ fontSize: 11 }}>{detail.algorithm}</Chip>
              {detail.pinned ? <Chip textStyle={{ fontSize: 11 }}>PINNED</Chip> : null}
              {detail.isCa ? (
                <Chip textStyle={{ fontSize: 11, color: VERIFIED_BLUE }}>CA</Chip>
              ) : null}
              {detail.distrusted ? <Chip textStyle={{ fontSize: 11 }}>DISTRUSTED</Chip> : null}
            </View>
            <Text variant="bodySmall" style={styles.muted}>
              Validity
            </Text>
            <Text variant="bodyMedium">{validityText}</Text>
            {detail.caName ? (
              <View style={[styles.nameRow, styles.verifiedBy]}>
                <Text variant="bodySmall" style={{ color: VERIFIED_BLUE }}>
                  Verified by {detail.caName}
                </Text>
                {!detail.pinned ? <VerifiedBadge size={12} /> : null}
              </View>
            ) : null}
          </Card.Content>
        </Card>

        <Card style={styles.card} mode="outlined">
          <Card.Title title="Distribution endpoints" titleVariant="titleMedium" />
          <Card.Content>
            {detail.endpoints.length === 0 && (
              <Text variant="bodyMedium" style={styles.muted}>
                No endpoints configured for this certificate.
              </Text>
            )}
            {detail.endpoints.map((ep) => {
              const isDefault = ep === detail.signedDefault;
              const isConfiguredMirror = detail.mirrors.includes(ep);
              return (
                <View key={ep} style={styles.endpointRow}>
                  <Text variant="bodySmall" style={[styles.mono, styles.flex]}>
                    {ep}
                  </Text>
                  <Chip textStyle={{ fontSize: 10 }}>{isDefault ? 'default' : 'mirror'}</Chip>
                  {isConfiguredMirror && !isDefault ? (
                    <Button
                      compact
                      mode="text"
                      disabled={endpointBusy}
                      onPress={() => void removeMirror(ep)}
                      textColor={theme.colors.error}
                    >
                      Remove
                    </Button>
                  ) : null}
                </View>
              );
            })}
            <View style={styles.endpointForm}>
              <TextInput
                mode="outlined"
                dense
                label="Mirror URL"
                placeholder="https://another-server.example"
                value={endpointUrl}
                onChangeText={setEndpointUrl}
                onSubmitEditing={() => void addMirror()}
                autoCapitalize="none"
                autoCorrect={false}
                keyboardType="url"
                disabled={endpointBusy}
                style={styles.endpointInput}
              />
              <Button
                mode="outlined"
                compact
                loading={endpointBusy}
                disabled={endpointBusy || !endpointUrl.trim()}
                onPress={() => void addMirror()}
              >
                Add
              </Button>
            </View>
          </Card.Content>
        </Card>

        <Button
          mode="contained"
          icon="cloud-download"
          loading={syncing}
          disabled={syncing}
          onPress={() => void doSync()}
          style={styles.syncBtn}
        >
          {syncing ? 'Syncing…' : 'Sync'}
        </Button>

        {result && (
          <Card style={styles.card} mode={result.errors.length > 0 ? 'contained' : 'outlined'}>
            <Card.Content>
              {result.errors.length === 0 ? (
                <Text variant="bodyMedium" style={{ color: theme.colors.primary }}>
                  Synced: {result.tcertsDownloaded} TCert(s), {result.statementsApplied} statement(s) applied.
                </Text>
              ) : (
                <Text variant="bodyMedium" style={{ color: theme.colors.error }}>
                  Synced with {result.errors.length} error(s): {result.tcertsDownloaded} TCert(s),{' '}
                  {result.statementsApplied} statement(s).
                </Text>
              )}
            </Card.Content>
          </Card>
        )}
        </> : (
          <StatementList rows={detail.statementGroups[tab]} dateFormat={dateFormat} />
        )}
      </ScrollView>

      <Portal>
        <Dialog visible={promptOpen} onDismiss={() => setPromptOpen(false)}>
          <Dialog.Title>Distribution server URL</Dialog.Title>
          <Dialog.Content>
            <Text variant="bodyMedium">
              This certificate has no endpoints. Enter a server URL to pull its certificates and statements from.
            </Text>
            <TextInput
              mode="outlined"
              label="https://…"
              value={promptUrl}
              onChangeText={setPromptUrl}
              autoCapitalize="none"
              autoCorrect={false}
              keyboardType="url"
              style={{ marginTop: 8 }}
            />
          </Dialog.Content>
          <Dialog.Actions>
            <Button onPress={() => setPromptOpen(false)}>Cancel</Button>
            <Button
              mode="contained"
              disabled={!promptUrl.trim()}
              onPress={() => {
                const url = promptUrl.trim();
                setPromptOpen(false);
                setPromptUrl('');
                void doSync(url);
              }}
            >
              Sync
            </Button>
          </Dialog.Actions>
        </Dialog>
      </Portal>
    </KeyboardAvoidingView>
  );
}

function StatementList({ rows, dateFormat }: { rows: StatementRow[]; dateFormat: DateFormat }) {
  if (rows.length === 0) {
    return <Text variant="bodyMedium" style={styles.muted}>No statements of this type belong to this TCert.</Text>;
  }
  return <>{rows.map((row, index) => (
    <Card key={`${row.type}-${row.target}-${row.issuedAt}-${index}`} style={styles.card} mode="outlined">
      <Card.Content>
        <Text variant="titleSmall">{row.type}</Text>
        <Text variant="bodySmall" style={styles.mono}>{row.target}</Text>
        <Text variant="bodySmall" style={styles.muted}>{formatEpoch(row.issuedAt, dateFormat)}</Text>
        {row.reason ? <Text variant="bodySmall">Reason: {row.reason}</Text> : null}
      </Card.Content>
    </Card>
  ))}</>;
}

const styles = StyleSheet.create({
  root: { flex: 1 },
  center: { flex: 1, alignItems: 'center', justifyContent: 'center' },
  content: { padding: 16, paddingBottom: 32 },
  card: { marginBottom: 12 },
  muted: { color: '#888' },
  mono: { fontFamily: 'monospace', fontSize: 12 },
  flex: { flex: 1 },
  rowChips: { flexDirection: 'row', gap: 6, marginVertical: 8, flexWrap: 'wrap' },
  nameRow: { flexDirection: 'row', alignItems: 'center', gap: 4 },
  verifiedBy: { marginTop: 6 },
  endpointRow: { flexDirection: 'row', alignItems: 'center', gap: 8, marginVertical: 2 },
  endpointForm: { flexDirection: 'row', alignItems: 'center', gap: 8, marginTop: 10 },
  endpointInput: { flex: 1 },
  syncBtn: { marginTop: 4 },
  tabs: { marginBottom: 12 },
});
