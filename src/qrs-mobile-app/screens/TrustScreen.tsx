/**
 * Trust screen: manage which certificates are trusted (pinned / CA / distrusted).
 * Every trust-affecting action requires the admin password.
 */
import React, { useCallback, useState } from 'react';
import { Alert, ScrollView, StyleSheet, View } from 'react-native';
import { useFocusEffect, useNavigation } from '@react-navigation/native';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';
import {
  Appbar,
  Button,
  Card,
  Chip,
  Dialog,
  IconButton,
  Menu,
  Portal,
  Text,
  TextInput,
  useTheme,
} from 'react-native-paper';
import { parseSignedObject, toBase64Url, fromBase64Url, type QrsRuntime } from 'qrs-core';
import { getQrs } from '../lib/runtime';
import { verifyAdminPassword, hasAdminPassword } from '../lib/password';
import { syncCert, type MobileSyncResult } from '../lib/sync';
import { PasswordDialog } from '../components/PasswordDialog';
import { VerifiedBadge } from '../components/VerifiedBadge';
import { VERIFIED_BLUE } from '../lib/theme';
import type { RootStackParamList } from '../navigation/types';
import { listArchivedTcertIds, removeTcertCascade, setTcertArchived } from '../lib/stores';

interface CertRow {
  tcertId: string;
  name: string;
  pinned: boolean;
  isCa: boolean;
  distrusted: boolean;
  trusted: boolean; // resolved trust state
  caName?: string;
  archived: boolean;
}

function shortId(id: string): string {
  return id.length > 22 ? `${id.slice(0, 11)}…${id.slice(-8)}` : id;
}

function truncateName(name: string, max = 34): string {
  const value = name.trim() || 'Unknown';
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

async function listCerts(qrs: QrsRuntime): Promise<CertRow[]> {
  const all = await qrs.deps.certificateStore.all();
  const archived = new Set(await listArchivedTcertIds());
  const rows: CertRow[] = [];
  for (const rec of all) {
    let parsed;
    try {
      parsed = parseSignedObject(rec.bytes);
    } catch {
      continue;
    }
    if (parsed.type !== 'tcert') continue;
    const data = parsed.data as unknown as {
      identity?: { name?: string };
    };
    const [pinned, isCa, distrusted, trust] = await Promise.all([
      qrs.deps.trustStore.isPinned(rec.tcertId),
      qrs.deps.trustStore.isCa(rec.tcertId),
      qrs.deps.trustStore.isDistrusted(rec.tcertId),
      qrs.trust.resolveTrust(rec.tcertId),
    ]);
    rows.push({
      tcertId: rec.tcertId,
      name: data.identity?.name ?? 'Unknown',
      pinned,
      isCa,
      distrusted,
      trusted: trust.state === 'valid',
      caName: trust.ca?.caName,
      archived: archived.has(rec.tcertId),
    });
  }
  rows.sort((a, b) => (a.trusted === b.trusted ? 0 : a.trusted ? -1 : 1));
  return rows;
}

type TrustOp = { kind: 'pin' | 'unpin' | 'addCa' | 'removeCa' | 'distrust' | 'trustAgain' | 'archive' | 'unarchive' | 'delete'; tcertId: string };
type PendingAction = TrustOp | null;

export function TrustScreen() {
  const theme = useTheme();
  const navigation = useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const [rows, setRows] = useState<CertRow[]>([]);
  const [needsSetup, setNeedsSetup] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [importB64, setImportB64] = useState('');
  const [importError, setImportError] = useState<string | null>(null);
  const [action, setAction] = useState<PendingAction>(null);
  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState<MobileSyncResult | null>(null);
  const [certMenu, setCertMenu] = useState<string | null>(null);
  const [showArchived, setShowArchived] = useState(false);

  const qrs = getQrs();

  const refresh = useCallback(async () => {
    setNeedsSetup(!(await hasAdminPassword()));
    setRows(await listCerts(qrs));
  }, [qrs]);

  // Refresh whenever the Trust tab gains focus (trust can change elsewhere).
  useFocusEffect(
    useCallback(() => {
      void refresh();
    }, [refresh])
  );

  /** Pull the namespace of one locally configured CA. */
  const doSync = async (tcertId: string): Promise<void> => {
    if (syncing) return;
    setSyncing(true);
    setSyncResult(null);
    const result: MobileSyncResult = await syncCert(qrs, tcertId);
    setSyncResult(result);
    setSyncing(false);
    await refresh();
    if (result.errors.length > 0) {
      Alert.alert('Sync finished with errors', result.errors.join('\n'));
    }
  };

  const runTrustOp = async (kind: TrustOp['kind'], tcertId: string): Promise<void> => {
    switch (kind) {
      case 'pin':
        await qrs.trust.pin(tcertId);
        break;
      case 'unpin':
        await qrs.trust.unpin(tcertId);
        break;
      case 'addCa':
        await qrs.trust.addCa(tcertId);
        break;
      case 'removeCa':
        await qrs.trust.removeCa(tcertId);
        break;
      case 'distrust':
        await qrs.trust.distrust(tcertId);
        break;
      case 'trustAgain':
        await qrs.trust.trustAgain(tcertId);
        break;
      case 'archive':
        await setTcertArchived(tcertId, true);
        break;
      case 'unarchive':
        await setTcertArchived(tcertId, false);
        break;
      case 'delete': {
        const result = await removeTcertCascade(tcertId);
        Alert.alert('Certificate deleted', `Removed ${result.removedTcertIds.length} certificate(s), including dependent orphaned certificates.`);
        break;
      }
    }
  };

  const confirmPassword = async (password: string): Promise<boolean> => {
    const ok = await verifyAdminPassword(password);
    if (!ok) return false;
    const current = action as { kind: NonNullable<PendingAction>['kind']; tcertId: string } | null;
    if (current) {
      await runTrustOp(current.kind, current.tcertId);
      setAction(null);
      await refresh();
    }
    return true;
  };

  const importCert = async (): Promise<void> => {
    setImportError(null);
    try {
      const bytes = fromBase64Url(importB64.trim());
      const parsed = parseSignedObject(bytes);
      if (parsed.type !== 'tcert') throw new Error('Not a TCert.');
      await qrs.deps.certificateStore.save(
        `${parsed.signerKeyId}:${parsed.data.certificateNumber as number}`,
        bytes,
      );
      setImportOpen(false);
      setImportB64('');
      await refresh();
    } catch (e) {
      setImportError(e instanceof Error ? e.message : 'Import failed.');
    }
  };

  return (
    <View style={styles.root}>
      <Appbar.Header>
        <Appbar.Content title="Trust" />
      </Appbar.Header>

      <ScrollView contentContainerStyle={styles.content}>
        {needsSetup && (
          <Card style={styles.card} mode="outlined">
            <Card.Title title="Configure admin password" titleVariant="titleMedium" />
            <Card.Content>
              <Text variant="bodyMedium">
                Trust actions (pin, add CA, distrust) are protected by an admin password. Set one in Settings to
                manage trust.
              </Text>
            </Card.Content>
          </Card>
        )}

        <View style={styles.headerRow}>
          <Text variant="titleMedium">{showArchived ? 'Archived certificates' : 'Certificates'} ({rows.filter((row) => row.archived === showArchived).length})</Text>
          <View style={styles.headerActions}>
            <Button compact onPress={() => setShowArchived((value) => !value)}>
              {showArchived ? 'Show active' : `Archived (${rows.filter((row) => row.archived).length})`}
            </Button>
            <Button icon="import" mode="outlined" onPress={() => setImportOpen(true)}>
              Import
            </Button>
          </View>
        </View>

        {syncResult && (
          <Card style={styles.card} mode={syncResult.errors.length > 0 ? 'contained' : 'outlined'}>
            <Card.Content>
              {syncResult.errors.length === 0 ? (
                <Text variant="bodyMedium" style={{ color: theme.colors.primary }}>
                  Synced: {syncResult.tcertsDownloaded} TCert(s), {syncResult.statementsApplied} statement(s) applied.
                </Text>
              ) : (
                <Text variant="bodyMedium" style={{ color: theme.colors.error }}>
                  Synced with {syncResult.errors.length} error(s) — {syncResult.tcertsDownloaded} TCert(s),{' '}
                  {syncResult.statementsApplied} statement(s).
                </Text>
              )}
            </Card.Content>
          </Card>
        )}

        {rows.filter((row) => row.archived === showArchived).map((r) => (
          <Card
            key={r.tcertId}
            style={styles.card}
            onPress={() => navigation.navigate('TcertDetail', { tcertId: r.tcertId })}
          >
            <Card.Title
              title={
                <View style={styles.nameRow}>
                  <Text variant="titleMedium" numberOfLines={1} ellipsizeMode="tail" style={styles.certName}>{truncateName(r.name)}</Text>
                  {r.trusted ? <VerifiedBadge /> : null}
                </View>
              }
              subtitle={shortId(r.tcertId)}
              right={() => (
                <View style={styles.cardRight}>
                  <View style={styles.chips}>
                  {r.pinned ? <Chip style={styles.chip} textStyle={{ fontSize: 10 }}>PINNED</Chip> : null}
                  {r.isCa ? (
                    <Chip textStyle={{ fontSize: 10, color: VERIFIED_BLUE }} style={styles.chip}>
                      CA
                    </Chip>
                  ) : null}
                  {r.distrusted ? <Chip textStyle={{ fontSize: 10 }}>DISTRUSTED</Chip> : null}
                  {r.archived ? <Chip textStyle={{ fontSize: 10 }}>ARCHIVED</Chip> : null}
                  </View>
                  <Menu
                    visible={certMenu === r.tcertId}
                    onDismiss={() => setCertMenu(null)}
                    anchor={<IconButton icon="dots-vertical" onPress={(event) => { event.stopPropagation(); setCertMenu(r.tcertId); }} />}
                  >
                    <Menu.Item onPress={() => { setCertMenu(null); setAction({ kind: r.archived ? 'unarchive' : 'archive', tcertId: r.tcertId }); }} title={r.archived ? 'Unarchive TCert' : 'Archive TCert'} />
                    <Menu.Item leadingIcon="delete" onPress={() => { setCertMenu(null); setAction({ kind: 'delete', tcertId: r.tcertId }); }} title="Delete TCert" />
                  </Menu>
                </View>
              )}
            />
            <Card.Content>
              {r.caName ? (
                <View style={styles.nameRow}>
                  <Text variant="bodySmall" style={{ color: VERIFIED_BLUE }}>
                    Verified by {r.caName}
                  </Text>
                  {r.trusted ? <VerifiedBadge size={12} /> : null}
                </View>
              ) : null}
              <View style={styles.actions}>
                {r.isCa && (
                  <Button
                    compact
                    icon="cloud-download"
                    loading={syncing}
                    disabled={syncing}
                    onPress={(e) => {
                      e.stopPropagation();
                      void doSync(r.tcertId);
                    }}
                  >
                    Sync CA
                  </Button>
                )}
                {r.pinned ? (
                  <Button compact onPress={() => setAction({ kind: 'unpin', tcertId: r.tcertId })}>
                    Unpin
                  </Button>
                ) : (
                  <Button compact icon="pin" onPress={() => setAction({ kind: 'pin', tcertId: r.tcertId })}>
                    Pin
                  </Button>
                )}
                {r.isCa ? (
                  <Button compact onPress={() => setAction({ kind: 'removeCa', tcertId: r.tcertId })}>
                    Remove CA
                  </Button>
                ) : (
                  <Button compact icon="shield-check" onPress={() => setAction({ kind: 'addCa', tcertId: r.tcertId })}>
                    Add CA
                  </Button>
                )}
                {r.distrusted ? (
                  <Button compact onPress={() => setAction({ kind: 'trustAgain', tcertId: r.tcertId })}>
                    Trust again
                  </Button>
                ) : (
                  <Button compact onPress={() => setAction({ kind: 'distrust', tcertId: r.tcertId })}>
                    Distrust
                  </Button>
                )}
              </View>
            </Card.Content>
          </Card>
        ))}

        {rows.filter((row) => row.archived === showArchived).length === 0 && (
          <Text variant="bodyMedium" style={{ color: theme.colors.onSurfaceVariant }}>
            No certificates yet. Import one to begin managing trust.
          </Text>
        )}
      </ScrollView>

      {action ? (
        <PasswordDialog
          visible
          title={actionLabel(action.kind)}
          message={action.kind === 'delete'
            ? 'This permanently deletes the TCert. Deleting a CA also removes its statements and any attested TCerts that have no independent trust path. Enter the admin password to continue.'
            : 'This requires the admin password.'}
          onCancel={() => setAction(null)}
          onConfirm={confirmPassword}
        />
      ) : null}

      <Portal>
        <Dialog visible={importOpen} onDismiss={() => setImportOpen(false)}>
          <Dialog.Title>Import a certificate</Dialog.Title>
          <Dialog.Content>
            <TextInput
              mode="outlined"
              label="TCert (base64url)"
              multiline
              numberOfLines={4}
              value={importB64}
              onChangeText={setImportB64}
              autoCapitalize="none"
              autoCorrect={false}
              style={{ fontFamily: 'monospace' }}
            />
            {importError ? <Text style={{ color: theme.colors.error }}>{importError}</Text> : null}
          </Dialog.Content>
          <Dialog.Actions>
            <Button onPress={() => setImportOpen(false)}>Cancel</Button>
            <Button mode="contained" disabled={!importB64.trim()} onPress={() => void importCert()}>
              Import
            </Button>
          </Dialog.Actions>
        </Dialog>
      </Portal>
    </View>
  );
}

function actionLabel(kind: TrustOp['kind']): string {
  const map: Record<string, string> = {
    pin: 'Pin certificate',
    unpin: 'Unpin certificate',
    addCa: 'Add as CA',
    removeCa: 'Remove CA',
    distrust: 'Distrust certificate',
    trustAgain: 'Trust again',
    archive: 'Archive TCert',
    unarchive: 'Unarchive TCert',
    delete: 'Delete TCert',
  };
  return map[kind] ?? 'Trust action';
}

const styles = StyleSheet.create({
  root: { flex: 1 },
  content: { padding: 16, paddingBottom: 40 },
  card: { marginBottom: 10 },
  headerRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 },
  headerActions: { flexDirection: 'row', gap: 8, alignItems: 'center' },
  nameRow: { flexDirection: 'row', alignItems: 'center' },
  certName: { flexShrink: 1, maxWidth: 240 },
  chips: { flexDirection: 'row', gap: 4, paddingRight: 8 },
  cardRight: { flexDirection: 'row', alignItems: 'center' },
  chip: { height: 24 },
  actions: { flexDirection: 'row', flexWrap: 'wrap', marginTop: 6 },
});
