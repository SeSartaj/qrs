import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Tabs,
  Tab,
  Card,
  CardContent,
  Chip,
  Grid,
  IconButton,
  Tooltip,
  Typography,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import EditNoteIcon from '@mui/icons-material/EditNote';
import SyncIcon from '@mui/icons-material/Sync';
import DownloadIcon from '@mui/icons-material/Download';
import { useTranslation } from 'react-i18next';
import { fromBase64Url, parseSignedObject } from 'qrs-core';
import type { DocumentSummary, RevocationState, SyncResult, TcertSummary, TrustState } from '@shared/types';
import { qrs, safe, shortId, formatDate } from '../api';
import { ObjectActions } from '../components/ObjectActions';
import { EndpointManager } from '../components/EndpointManager';
import { SdocTable } from '../components/SdocTable';
import { SignSdocPage } from './SignSdocPage';
import { SdocDetailPage } from './SdocDetailPage';
import { AttestTcertPage } from './AttestTcertPage';
import { AttestationDetailPage } from './AttestationDetailPage';
import { OverflowMenu } from '../components/OverflowMenu';

type ShowNotice = (severity: 'success' | 'error' | 'info', text: string) => void;

interface DocumentsPageProps {
  showNotice: ShowNotice;
  onVerify: (bytesB64: string) => void;
  initialTcertId?: string | null;
  onInitialTcertOpened?: () => void;
}

export function DocumentsPage({ showNotice, onVerify, initialTcertId, onInitialTcertOpened }: DocumentsPageProps) {
  const { t } = useTranslation();
  const [tcerts, setTcerts] = useState<TcertSummary[]>([]);
  const [knownTcerts, setKnownTcerts] = useState<TcertSummary[]>([]);
  const [docs, setDocs] = useState<DocumentSummary[]>([]);
  const [selectedTcertId, setSelectedTcertId] = useState<string | null>(null);
  const [signing, setSigning] = useState(false);
  const [selectedSdocId, setSelectedSdocId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<DocumentSummary | null>(null);
  const [pendingAttachments, setPendingAttachments] = useState<Record<string, number>>({});
  const [attesting, setAttesting] = useState(false);
  const [selectedAttestationTarget, setSelectedAttestationTarget] = useState<string | null>(null);
  const [certTab, setCertTab] = useState('sdocs');
  const [trustState, setTrustState] = useState<TrustState | null>(null);
  const [revocationState, setRevocationState] = useState<RevocationState | null>(null);
  const [archivedTcerts, setArchivedTcerts] = useState<string[]>([]);
  const [pendingBlock, setPendingBlock] = useState<{ sdocId: string; action: 'block' | 'unblock' } | null>(null);

  const reload = useCallback(async () => {
    const [tRes, dRes, trustRes, revocationRes, configRes] = await Promise.all([
      safe(qrs().certificates.list()),
      safe(qrs().documents.list()),
      safe(qrs().trust.state()), safe(qrs().revocation.state()),
      safe(qrs().config.get()),
    ]);
    if (tRes.ok) {
      setKnownTcerts(tRes.value);
      setTcerts(tRes.value.filter((c) => c.own)); // sign with our own certs only
      const counts = await Promise.all(tRes.value.map(async (cert) => {
        const result = await safe(qrs().attachments.pendingForTcert(cert.tcertId));
        return result.ok ? [cert.tcertId, result.value] as const : null;
      }));
      setPendingAttachments(Object.fromEntries(counts.filter((entry): entry is readonly [string, number] => entry !== null)));
    }
    if (dRes.ok) setDocs(dRes.value);
    if (trustRes.ok) setTrustState(trustRes.value);
    if (revocationRes.ok) setRevocationState(revocationRes.value);
    if (configRes.ok) setArchivedTcerts(configRes.value.archivedTcerts ?? []);
  }, []);

  useEffect(() => {
    void (async () => {
      await reload();
      const initial = initialTcertId ?? (window as unknown as { __qrsInitialTcert?: string }).__qrsInitialTcert;
      if (initial) setSelectedTcertId(initial);
      if (initialTcertId) onInitialTcertOpened?.();
    })();
    // Dev/screenshot: the host injects __qrsInitialTcert just after load, so re-check.
    const t = setTimeout(() => {
      const initial = (window as unknown as { __qrsInitialTcert?: string }).__qrsInitialTcert;
      if (initial) setSelectedTcertId(initial);
    }, 1200);
    return () => clearTimeout(t);
  }, [reload, initialTcertId, onInitialTcertOpened]);

  const selectedTcert = useMemo(
    () => (selectedTcertId ? (tcerts.find((x) => x.tcertId === selectedTcertId) ?? null) : null),
    [tcerts, selectedTcertId]
  );

  /** Documents issued under the selected TCert (or all when none selected). */
  const selectedDocs = useMemo(
    () => (selectedTcertId ? docs.filter((d) => d.tcertId === selectedTcertId) : docs),
    [docs, selectedTcertId]
  );

  const signedStatements = useMemo(() => {
    if (!selectedTcert) return [];
    const signedBySelectedKey = (bytesB64?: string, byKeyId?: string, byTcertId?: string): boolean => {
      if (byTcertId === selectedTcert.tcertId || byKeyId === selectedTcert.keyId) return true;
      if (!bytesB64) return false;
      try {
        return parseSignedObject(fromBase64Url(bytesB64)).signerKeyId === selectedTcert.keyId;
      } catch {
        return false;
      }
    };
    return [
      ...(trustState?.attestations
        .filter((x) => x.caTcertId === selectedTcert.tcertId)
        .map((x) => ({ type: 'Attestation', target: x.targetTcertId, issuedAt: x.issuedAt, reason: undefined as string | undefined, bytesB64: x.bytesB64 })) ?? []),
      ...(revocationState?.revokedTcerts
        .filter((x) => signedBySelectedKey(x.bytesB64, x.byKeyId, x.byTcertId))
        .map((x) => ({ type: `TCert revocation (${x.type})`, target: x.tcertId, issuedAt: x.issuedAt, reason: x.reason, bytesB64: x.bytesB64 })) ?? []),
      ...(revocationState?.revokedAttestations
        .filter((x) => x.caTcertId === selectedTcert.tcertId)
        .map((x) => ({ type: 'Attestation revocation', target: x.targetTcertId, issuedAt: x.issuedAt, reason: x.reason, bytesB64: x.bytesB64 })) ?? []),
      ...(revocationState?.revokedKeys
        .filter((x) => signedBySelectedKey(x.bytesB64, x.byKeyId, x.byTcertId))
        .map((x) => ({ type: 'Key revocation', target: x.keyId, issuedAt: x.issuedAt, reason: x.reason, bytesB64: x.bytesB64 })) ?? []),
      ...(revocationState?.sdocStatements
        .filter((x) => signedBySelectedKey(x.bytesB64, x.byKeyId, x.byTcertId))
        .map((x) => ({
          type: x.action === 'blockSdoc' ? 'SDoc block' : 'SDoc unblock',
          target: x.sdocId,
          issuedAt: x.issuedAt,
          reason: x.reason,
          bytesB64: x.bytesB64,
        })) ?? []),
      ...(revocationState?.blockedSdocs
        .filter((x) => {
          const alreadyInHistory = revocationState.sdocStatements.some((statement) => statement.action === 'blockSdoc' && statement.sdocId === x.sdocId && statement.issuedAt === x.issuedAt);
          if (alreadyInHistory) return false;
          if (signedBySelectedKey(x.bytesB64, x.byKeyId, x.byTcertId)) return true;
          // Older desktop versions stored only the blocked SDoc id and time.
          // The Documents UI only offered blocking for SDocs under the open
          // TCert, so use the target document as a display-only attribution.
          if (x.bytesB64 || x.byKeyId || x.byTcertId) return false;
          return docs.some((doc) => doc.sdocId === x.sdocId && doc.tcertId === selectedTcert.tcertId);
        })
        .map((x) => ({
          type: x.bytesB64 ? 'SDoc block' : 'SDoc block (legacy)',
          target: x.sdocId,
          issuedAt: x.issuedAt,
          reason: x.reason,
          bytesB64: x.bytesB64,
        })) ?? []),
    ].sort((a, b) => b.issuedAt - a.issuedAt);
  }, [docs, revocationState, selectedTcert, trustState]);

  const docCountFor = (tcertId: string): number => docs.filter((d) => d.tcertId === tcertId).length;

  /** Shared handling of a sync result: show errors or a summary, then refresh. */
  const applySyncResult = (res: { ok: true; value: SyncResult } | { ok: false; error: string }): void => {
    if (!res.ok) {
      setError(`Sync failed: ${res.error}`);
      showNotice('error', 'Sync failed — see the red alert above for details');
      return;
    }
    if (res.value.errors.length > 0) {
      // Show every message so the user can read/debug them.
      setError(`Sync finished with ${res.value.errors.length} error(s):\n\n${res.value.errors.join('\n')}`);
      showNotice('error', `Sync finished with ${res.value.errors.length} error(s) — see the red alert above`);
      void reload();
      return;
    }
    const parts: string[] = [];
    if (res.value.uploaded > 0) parts.push(`uploaded ${res.value.uploaded}`);
    if (res.value.downloaded > 0) parts.push(`downloaded ${res.value.downloaded}`);
    if (res.value.applied > 0) parts.push(`applied ${res.value.applied}`);
    const summary = parts.length > 0
      ? `Sync: ${parts.join(', ')}`
      : res.value.pending > 0
        ? `Sync completed — ${res.value.pending} upload(s) still pending`
        : 'Sync completed — nothing new to upload or download';
    showNotice(
      parts.length > 0 ? 'success' : 'info',
      summary
    );
    void reload();
  };

  /** Sync the selected TCert's distribution namespace. */
  const syncCert = async (tcertId: string): Promise<void> => {
    setBusy(true);
    setError(null);
    const res = await safe(qrs().attachments.syncTcert(tcertId));
    setBusy(false);
    applySyncResult(res);
  };

  const copy = async (text: string): Promise<void> => {
    await navigator.clipboard.writeText(text);
    showNotice('info', t('common.copied'));
  };

  /** Promote/revoke the selected (own) cert as a CA — its schema-less certs attest others. */
  const toggleCa = async (): Promise<void> => {
    if (!selectedTcert) return;
    const next = !selectedTcert.isCa;
    const res = await safe(next ? qrs().trust.addCa(selectedTcert.tcertId) : qrs().trust.removeCa(selectedTcert.tcertId));
    if (!res.ok) {
      showNotice('error', `CA action failed: ${res.error}`);
      return;
    }
    showNotice('success', next ? 'Added as CA' : 'Removed as CA');
    void reload();
  };

  const revokeSelectedTcert = async (): Promise<void> => {
    if (!selectedTcert || !window.confirm(`Revoke TCert ${selectedTcert.name}?`)) return;
    const res = await safe(qrs().revocation.revokeTcert({ signerKeyId: selectedTcert.keyId, targetTcertId: selectedTcert.tcertId, type: 'retrospective' }));
    if (res.ok) { showNotice('success', 'TCert revoked'); void reload(); } else showNotice('error', `Revoke failed: ${res.error}`);
  };

  const blockSdoc = async (sdocId: string, unblock = false): Promise<void> => {
    if (pendingBlock || !selectedTcert || !window.confirm(`${unblock ? 'Unblock' : 'Block'} SDoc ${shortId(sdocId)}?`)) return;
    setPendingBlock({ sdocId, action: unblock ? 'unblock' : 'block' });
    try {
      const input = { signerKeyId: selectedTcert.keyId, targetSdocId: sdocId };
      const res = await safe(unblock ? qrs().revocation.unblockSdoc(input) : qrs().revocation.blockSdoc(input));
      if (res.ok) {
        showNotice('success', unblock ? 'SDoc unblocked' : 'SDoc blocked');
        await reload();
      } else {
        showNotice('error', `${unblock ? 'Unblock' : 'Block'} failed: ${res.error}`);
      }
    } finally {
      setPendingBlock(null);
    }
  };

  const revokeAttestation = async (targetTcertId: string): Promise<void> => {
    if (!selectedTcert || !window.confirm(`Revoke the attestation for ${shortId(targetTcertId)}?`)) return;
    const res = await safe(qrs().revocation.revokeAttestation({ caTcertId: selectedTcert.tcertId, targetTcertId, reason: 'Attestation revoked' }));
    if (res.ok) { showNotice('success', 'Attestation revoked'); void reload(); } else showNotice('error', `Revoke failed: ${res.error}`);
  };

  const archiveTcert = async (tcertId: string): Promise<void> => {
    const config = await safe(qrs().config.get());
    if (!config.ok) return showNotice('error', `Could not archive TCert: ${config.error}`);
    await qrs().config.set({ ...config.value, archivedTcerts: [...new Set([...(config.value.archivedTcerts ?? []), tcertId])] });
    showNotice('success', 'TCert archived');
    void reload();
  };

  const exportStatements = async (): Promise<void> => {
    if (!selectedTcert) return;
    // Apply state-changing statements oldest-first on the verifier. In
    // particular, an unblock must be processed after the block it supersedes.
    const statements = [...signedStatements].reverse().map((statement) => statement.bytesB64).filter((bytes): bytes is string => Boolean(bytes));
    if (statements.length === 0) {
      showNotice('info', 'This TCert has no exportable signed statements');
      return;
    }
    const attestedTcertIds = new Set(
      selectedTcert.isCa
        ? (trustState?.attestations ?? [])
            .filter((attestation) => attestation.caTcertId === selectedTcert.tcertId && Boolean(attestation.bytesB64))
            .map((attestation) => attestation.targetTcertId)
        : [],
    );
    const missingAttestedTcerts = [...attestedTcertIds].filter(
      (tcertId) => !knownTcerts.some((cert) => cert.tcertId === tcertId),
    );
    if (missingAttestedTcerts.length > 0) {
      showNotice('error', `Cannot export complete CA bundle: ${missingAttestedTcerts.length} attested TCert(s) are not stored locally`);
      return;
    }
    // Only attestation targets are additional transport dependencies. Never add
    // other local TCerts merely because they share the selected signer's key.
    const additionalTcertBytesB64 = knownTcerts
      .filter((cert) => cert.tcertId !== selectedTcert.tcertId && attestedTcertIds.has(cert.tcertId))
      .map((cert) => cert.bytesB64);
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const result = await safe(qrs().objects.exportBundle({ tcertBytesB64: selectedTcert.bytesB64, additionalTcertBytesB64, statementBytesB64: [...new Set(statements)], suggestedName: `${selectedTcert.tcertId}-${stamp}` }));
    showNotice(result.ok && result.value.saved ? 'success' : 'error', result.ok && result.value.saved ? 'TCert statements exported' : `Export failed: ${result.ok ? 'cancelled' : result.error}`);
  };

  const hasStatements = (tcertId: string): boolean => Boolean(
    trustState?.attestations.some((a) => a.caTcertId === tcertId || a.targetTcertId === tcertId) ||
    trustState?.cas.includes(tcertId) ||
    tcerts.find((cert) => cert.tcertId === tcertId)?.revoked
  );

  const removeTcert = async (cert: TcertSummary): Promise<void> => {
    const hasDocs = docs.some((doc) => doc.tcertId === cert.tcertId);
    if (hasDocs || hasStatements(cert.tcertId)) return void archiveTcert(cert.tcertId);
    if (!window.confirm(`Delete TCert ${cert.name}? This cannot be undone.`)) return;
    const result = await safe(qrs().certificates.remove(cert.tcertId));
    if (result.ok) { showNotice('success', 'TCert deleted'); void reload(); } else showNotice('error', `Delete failed: ${result.error}`);
  };

  const openTcert = (tcertId: string): void => {
    setSelectedTcertId(tcertId);
    setCertTab('sdocs');
    setSigning(false);
    setResult(null);
    setError(null);
  };

  /** Called after a successful sign on the dedicated Sign page. */
  const onIssued = (doc: DocumentSummary): void => {
    setSigning(false);
    setSelectedSdocId(doc.sdocId);
    void reload();
  };

  /* ------------------------------------------------ TCert detail view */
  if (selectedTcert) {
    const validityText =
      selectedTcert.validity?.validAfter !== undefined || selectedTcert.validity?.validBefore !== undefined
        ? `${selectedTcert.validity.validAfter !== undefined ? formatDate(selectedTcert.validity.validAfter) : '…'} → ${
            selectedTcert.validity.validBefore !== undefined ? formatDate(selectedTcert.validity.validBefore) : '…'
          }`
        : '—';

    // Dedicated Sign page: when the user clicks "Sign new document".
    if (signing) {
      return (
        <SignSdocPage
          tcert={selectedTcert}
          onBack={() => setSigning(false)}
          onIssued={onIssued}
          showNotice={showNotice}
        />
      );
    }
    if (attesting) return <AttestTcertPage ca={selectedTcert} onBack={() => setAttesting(false)} showNotice={showNotice} />;
    if (selectedAttestationTarget) {
      const attestation = trustState?.attestations.find((a) => a.caTcertId === selectedTcert.tcertId && a.targetTcertId === selectedAttestationTarget);
      const target = knownTcerts.find((cert) => cert.tcertId === selectedAttestationTarget) ?? null;
      if (attestation) return <AttestationDetailPage ca={selectedTcert} target={target} attestation={attestation} onBack={() => setSelectedAttestationTarget(null)} showNotice={showNotice} />;
    }

    // Dedicated SDoc details page.
    if (selectedSdocId) {
      return (
        <SdocDetailPage
          sdocId={selectedSdocId}
          onBack={() => setSelectedSdocId(null)}
          onVerify={onVerify}
          showNotice={showNotice}
          signerKeyId={selectedTcert.keyId}
        />
      );
    }

    return (
      <Box>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Tooltip title={t('documents.backToCerts')}>
              <IconButton onClick={() => setSelectedTcertId(null)}>
                <ArrowBackIcon />
              </IconButton>
            </Tooltip>
            <Typography variant="h5">{selectedTcert.name}</Typography>
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {(selectedTcert.endpoints?.length ?? 0) > 0 && (
              <Button
                variant="outlined"
                size="small"
                startIcon={<SyncIcon />}
                onClick={() => void syncCert(selectedTcert.tcertId)}
                disabled={busy}
              >
                Sync
              </Button>
            )}
            {selectedTcert.hasSchema && (
              <Button
                variant="contained"
                size="small"
                startIcon={<EditNoteIcon />}
                onClick={() => setSigning(true)}
                disabled={Boolean(selectedTcert.revoked)}
              >
                {t('documents.signNew')}
              </Button>
            )}
          </Box>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 2, whiteSpace: 'pre-line', fontFamily: 'monospace', fontSize: 13 }} onClose={() => setError(null)}>
            {error}
          </Alert>
        )}
        {(pendingAttachments[selectedTcert.tcertId] ?? 0) > 0 && (
          <Alert severity="info" sx={{ mb: 2 }}>
            {pendingAttachments[selectedTcert.tcertId]} attachment upload(s) waiting for this TCert — they will sync automatically when the network is available.
          </Alert>
        )}
        {result && (
          <Alert severity="success" sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1 }} onClose={() => setResult(null)}>
            <Box sx={{ flexGrow: 1 }}>
              {t('documents.issued')} <b>{shortId(result.sdocId)}</b> ({result.sizeBytes} {t('documents.bytes')}).
            </Box>
            <ObjectActions type="sdoc" bytesB64={result.bytesB64} fileName={result.sdocId} qrTitle="SDoc QR" showNotice={showNotice} />
          </Alert>
        )}

        <Card sx={{ mb: 2 }}>
          <CardContent>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, alignItems: 'center' }}>
              <Box>
                <Typography variant="body2" color="text.secondary">
                  {t('documents.name')}
                </Typography>
                <Typography variant="subtitle1">{selectedTcert.name}</Typography>
              </Box>
              <Box>
                <Typography variant="body2" color="text.secondary">
                  {t('documents.certificate')}
                </Typography>
                <Typography variant="subtitle1" sx={{ fontFamily: 'monospace', fontSize: 13 }}>
                  {shortId(selectedTcert.tcertId)}
                </Typography>
              </Box>
              <Box>
                <Typography variant="body2" color="text.secondary">
                  {t('documents.algorithm')}
                </Typography>
                <Typography variant="subtitle1">{selectedTcert.algorithm}</Typography>
              </Box>
              <Box>
                <Typography variant="body2" color="text.secondary">
                  {t('documents.validity')}
                </Typography>
                <Typography variant="subtitle1">{validityText}</Typography>
              </Box>
              <Box sx={{ ml: 'auto', display: 'flex', alignItems: 'center' }}>
                <Chip label={`${selectedDocs.length} ${t('documents.docs').toLowerCase()}`} size="small" />
                <Chip
                  label={`${pendingAttachments[selectedTcert.tcertId] ?? 0} pending attachment upload${pendingAttachments[selectedTcert.tcertId] === 1 ? '' : 's'}`}
                  size="small"
                  color={(pendingAttachments[selectedTcert.tcertId] ?? 0) > 0 ? 'warning' : 'default'}
                  sx={{ ml: 1 }}
                />
                <Button
                  size="small"
                  color={selectedTcert.isCa ? 'secondary' : 'primary'}
                  variant={selectedTcert.isCa ? 'contained' : 'outlined'}
                  onClick={() => void toggleCa()}
                  sx={{ ml: 1 }}
                >
                  {selectedTcert.isCa ? 'Remove CA' : 'Add as CA'}
                </Button>
                <ObjectActions
                  type="tcert"
                  bytesB64={selectedTcert.bytesB64}
                  fileName={selectedTcert.name || selectedTcert.tcertId}
                  qrTitle="TCert QR"
                  showNotice={showNotice}
                />
            <OverflowMenu actions={[{ label: 'Revoke TCert', color: 'error', onClick: () => void revokeSelectedTcert() }, ...(selectedTcert.isCa ? [{ label: 'Attest a TCert', onClick: () => setAttesting(true) }] : [])]} />
              </Box>
            </Box>
          </CardContent>
        </Card>

        <EndpointManager tcert={selectedTcert} onChanged={() => void reload()} showNotice={showNotice} />

        <Tabs value={certTab} onChange={(_, value: string) => setCertTab(value)} sx={{ mb: 2 }}>
          <Tab value="sdocs" label="Signed SDocs" />
          <Tab value="statements" label={`Statements (${signedStatements.length})`} />
          {selectedTcert.isCa && <Tab value="attestations" label={`Attestations (${trustState?.attestations.filter((a) => a.caTcertId === selectedTcert.tcertId).length ?? 0})`} />}
        </Tabs>

        {certTab === 'statements' ? (
          <Box>
            <Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 2 }}>
              <Button variant="outlined" startIcon={<DownloadIcon />} onClick={() => void exportStatements()} disabled={signedStatements.length === 0}>
                Export TCert statements
              </Button>
            </Box>
            {signedStatements.length === 0 ? (
              <Alert severity="info">This TCert has not signed any statements.</Alert>
            ) : signedStatements.map((statement, index) => (
              <Card key={`${statement.type}-${statement.target}-${statement.issuedAt}-${index}`} sx={{ mb: 1 }}>
                <CardContent sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
                  <Typography sx={{ minWidth: 190, fontWeight: 600 }}>{statement.type}</Typography>
                  <Typography sx={{ flex: 1, fontFamily: 'monospace' }}>{shortId(statement.target)}</Typography>
                  <Typography variant="body2" color="text.secondary">{formatDate(statement.issuedAt)}</Typography>
                  {statement.bytesB64 ? <ObjectActions type="statement" bytesB64={statement.bytesB64} fileName={`${selectedTcert.name}-statement`} qrTitle="Statement QR" showNotice={showNotice} /> : <Chip size="small" color="warning" label="Signed bytes unavailable" />}
                  {statement.reason && <Typography variant="body2" sx={{ width: '100%' }}>Reason: {statement.reason}</Typography>}
                </CardContent>
              </Card>
            ))}
          </Box>
        ) : certTab === 'attestations' ? (
          <Card>
            <CardContent>
              {(trustState?.attestations.filter((a) => a.caTcertId === selectedTcert.tcertId) ?? []).map((attestation) => (
                <Box key={attestation.statementId ?? `${attestation.caTcertId}-${attestation.targetTcertId}`} onClick={() => setSelectedAttestationTarget(attestation.targetTcertId)} sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1, cursor: 'pointer' }}>
                  <Typography sx={{ flex: 1 }}>CA (attester): {selectedTcert.name || shortId(selectedTcert.tcertId)} → Attested TCert: {knownTcerts.find((cert) => cert.tcertId === attestation.targetTcertId)?.name ?? shortId(attestation.targetTcertId)}</Typography>
                  <Typography variant="body2" color="text.secondary">{formatDate(attestation.issuedAt)}</Typography>
                  {revocationState?.revokedAttestations.some((x) => x.caTcertId === selectedTcert.tcertId && x.targetTcertId === attestation.targetTcertId)
                    ? <Chip size="small" color="error" label="Revoked" />
                    : <OverflowMenu actions={[{ label: 'Revoke attestation', color: 'error', onClick: () => void revokeAttestation(attestation.targetTcertId) }]} />}
                </Box>
              ))}
              {(trustState?.attestations.filter((a) => a.caTcertId === selectedTcert.tcertId).length ?? 0) === 0 && <Alert severity="info">This TCert has not attested any TCerts.</Alert>}
            </CardContent>
          </Card>
        ) : (
          <>

        {!selectedTcert.hasSchema && (
          <Alert severity="info" sx={{ mb: 2 }}>
            This certificate has no document schema — it is a CA/meta certificate used for attestation, revocation and blocking. It cannot sign documents.
          </Alert>
        )}

        <Typography variant="h6" sx={{ mb: 1 }}>
          {t('documents.issuedBy')} ({selectedDocs.length})
        </Typography>
        <SdocTable docs={selectedDocs} onVerify={onVerify} copy={copy} t={t} onOpen={setSelectedSdocId} onBlock={(id, unblock) => void blockSdoc(id, unblock)} pendingBlock={pendingBlock} />
          </>
        )}
      </Box>
    );
  }

  /* ------------------------------------------------ certificate list */
  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Box>
          <Typography variant="h5">{t('documents.title')}</Typography>
          <Typography variant="body2" color="text.secondary">
            {t('documents.chooseCertHint')}
          </Typography>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2, whiteSpace: 'pre-line', fontFamily: 'monospace', fontSize: 13 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}
      {tcerts.length === 0 && (
        <Alert severity="info" sx={{ mb: 2 }}>
          {t('documents.noCertsYet')} {t('documents.createCertInSettings')}
        </Alert>
      )}

      <Grid container spacing={2}>
        {tcerts.filter((cert) => !archivedTcerts.includes(cert.tcertId)).map((cert) => (
          <Grid size={{ xs: 12, sm: 6, md: 4 }} key={cert.tcertId}>
            <Card sx={{ height: '100%', cursor: 'pointer' }} onClick={() => openTcert(cert.tcertId)}>
              <CardContent>
                <Typography variant="h6" sx={{ mb: 0.5 }}>
                  {cert.name}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  {cert.tcertId.split(':')[0].slice(0, 12)}…
                </Typography>
                <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 1 }}>
                  <Chip size="small" label={`#${cert.certificateNumber}`} />
                  <Chip size="small" label={cert.algorithm} variant="outlined" />
                  {cert.revoked && <Chip size="small" color="error" label="Revoked" />}
                </Box>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box sx={{ display: 'flex', gap: 0.5, alignItems: 'center' }}>
                    <Chip size="small" color={cert.revoked ? 'error' : 'primary'} variant="outlined" label={cert.revoked ? 'Revoked' : `${docCountFor(cert.tcertId)} ${t('documents.docs').toLowerCase()}`} />
                    <Chip
                      size="small"
                      color={(pendingAttachments[cert.tcertId] ?? 0) > 0 ? 'warning' : 'default'}
                      label={`${pendingAttachments[cert.tcertId] ?? 0} pending upload${pendingAttachments[cert.tcertId] === 1 ? '' : 's'}`}
                    />
                  </Box>
                  <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                    {shortId(cert.tcertId)}
                  </Typography>
                  <OverflowMenu actions={[{ label: docs.some((doc) => doc.tcertId === cert.tcertId) || hasStatements(cert.tcertId) ? 'Archive TCert' : 'Delete TCert', color: 'error', onClick: () => void removeTcert(cert) }]} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>
    </Box>
  );
}
