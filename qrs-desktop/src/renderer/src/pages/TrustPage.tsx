import { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  FormControl,
  Grid,
  InputLabel,
  MenuItem,
  Select,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { StatementResultDto, TcertSummary, TrustState } from '@shared/types';
import { qrs, safe, shortId } from '../api';
import { ObjectActions } from '../components/ObjectActions';
import { QRCodeDialog, buildQrPayload } from '../components/QRCodeDialog';

type ShowNotice = (severity: 'success' | 'error' | 'info', text: string) => void;

export function TrustPage({ showNotice }: { showNotice: ShowNotice }) {
  const { t } = useTranslation();
  const [tcerts, setTcerts] = useState<TcertSummary[]>([]);
  const [trust, setTrust] = useState<TrustState | null>(null);
  const [importB64, setImportB64] = useState('');
  const [caTcertId, setCaTcertId] = useState('');
  const [targetTcertId, setTargetTcertId] = useState('');
  const [claimsJson, setClaimsJson] = useState('');
  const [attestQr, setAttestQr] = useState<StatementResultDto | null>(null);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    const [tRes, s] = await Promise.all([safe(qrs().certificates.list()), safe(qrs().trust.state())]);
    if (tRes.ok) setTcerts(tRes.value); // all certs (attestation needs our own CA + targets)
    if (s.ok) setTrust(s.value);
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const run = async (label: string, p: Promise<unknown>): Promise<void> => {
    const res = await safe(p);
    if (!res.ok) {
      showNotice('error', `${label}: ${res.error}`);
    } else {
      showNotice('success', label);
    }
    void reload();
  };

  const importTcert = async (): Promise<void> => {
    setError(null);
    if (!importB64.trim()) return;
    const res = await safe(qrs().certificates.import(importB64.trim()));
    if (!res.ok) {
      setError(res.error);
      return;
    }
    setImportB64('');
    showNotice('success', `Imported TCert ${shortId(res.value.tcertId)}`);
    void reload();
  };

  const attest = async (): Promise<void> => {
    setError(null);
    if (!caTcertId || !targetTcertId) {
      setError('Select a CA certificate and a target certificate.');
      return;
    }
    let claims: Record<string, unknown> | undefined;
    if (claimsJson.trim()) {
      try {
        claims = JSON.parse(claimsJson) as Record<string, unknown>;
      } catch {
        setError('Claims must be valid JSON.');
        return;
      }
    }
    const res = await safe(qrs().trust.attest({ caTcertId, targetTcertId, claims }));
    if (!res.ok) {
      setError(res.error);
      return;
    }
    setClaimsJson('');
    setAttestQr(res.value);
    showNotice('success', t('trust.attestationIssued'));
    if (res.value.published && res.value.endpoints && res.value.endpoints.length > 0) {
      showNotice('success', `Published to ${res.value.endpoints.join(', ')}`);
    } else {
      showNotice('info', 'Not published — no online_endpoint on the CA certificate');
    }
    void reload();
  };

  const caList = tcerts.filter((t) => trust?.cas.includes(t.tcertId));
  // The trust management table shows received certificates; our own (key-holding)
  // certificates live on the Documents page. The attestation tool above still
  // uses all certs because you attest with your own CA and targets.
  const received = tcerts.filter((t) => !t.own);

  return (
    <Box>
      <Typography variant="h5" sx={{ mb: 3 }}>
        {t('trust.title')}
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Grid container spacing={2} sx={{ mb: 2 }}>
        <Grid size={{ xs: 12, md: 6 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 1 }}>
                {t('trust.importTcert')}
              </Typography>
              <TextField
                label={t('trust.tcertB64')}
                multiline
                minRows={2}
                fullWidth
                value={importB64}
                onChange={(e) => setImportB64(e.target.value)}
                sx={{ mb: 1, fontFamily: 'monospace' }}
              />
              <Button variant="contained" onClick={importTcert} disabled={!importB64.trim()}>
                {t('common.create')}
              </Button>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 1 }}>
                {t('trust.attest')}
              </Typography>
              <FormControl fullWidth size="small" sx={{ mb: 1 }}>
                <InputLabel>{t('trust.caCertificate')}</InputLabel>
                <Select value={caTcertId} label={t('trust.caCertificate')} onChange={(e) => setCaTcertId(e.target.value)}>
                  {caList.map((tRes) => (
                    <MenuItem key={tRes.tcertId} value={tRes.tcertId}>
                      {tRes.name} ({shortId(tRes.tcertId)})
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              <FormControl fullWidth size="small" sx={{ mb: 1 }}>
                <InputLabel>{t('trust.targetCertificate')}</InputLabel>
                <Select value={targetTcertId} label={t('trust.targetCertificate')} onChange={(e) => setTargetTcertId(e.target.value)}>
                  {received.map((tRes) => (
                    <MenuItem key={tRes.tcertId} value={tRes.tcertId}>
                      {tRes.name} ({shortId(tRes.tcertId)})
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              <TextField
                label={t('trust.claimsJson')}
                size="small"
                fullWidth
                value={claimsJson}
                onChange={(e) => setClaimsJson(e.target.value)}
                placeholder='{"role": "inspector"}'
                sx={{ mb: 1 }}
              />
              <Button variant="contained" onClick={attest}>
                {t('trust.issueAttestation')}
              </Button>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <TableContainer component={Card}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>{t('trust.tcertCol')}</TableCell>
              <TableCell>{t('trust.documentCol')}</TableCell>
              <TableCell>{t('trust.trustCol')}</TableCell>
              <TableCell align="right">{t('trust.actionsCol')}</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {received.map((tRes) => (
              <TableRow key={tRes.tcertId} hover>
                <TableCell sx={{ whiteSpace: 'nowrap' }}>
                  <ObjectActions type="tcert" bytesB64={tRes.bytesB64} fileName={tRes.name || tRes.tcertId} qrTitle="TCert QR" showNotice={showNotice} />
                  {shortId(tRes.tcertId)}
                </TableCell>
                <TableCell>
                  {tRes.name}
                  <Typography variant="caption" display="block" color="text.secondary">
                    {tRes.hashAlgorithm ?? ''}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                    <Chip
                      size="small"
                      label={t('trust.pinned')}
                      color={tRes.pinned ? 'success' : 'default'}
                      variant={tRes.pinned ? 'filled' : 'outlined'}
                    />
                    <Chip
                      size="small"
                      label={t('trust.ca')}
                      color={tRes.isCa ? 'secondary' : 'default'}
                      variant={tRes.isCa ? 'filled' : 'outlined'}
                    />
                    <Chip
                      size="small"
                      label={t('trust.distrusted')}
                      color={tRes.distrusted ? 'error' : 'default'}
                      variant={tRes.distrusted ? 'filled' : 'outlined'}
                    />
                    {tRes.revoked && <Chip size="small" label={t('trust.revoked')} color="error" variant="outlined" />}
                  </Box>
                </TableCell>
                <TableCell align="right" sx={{ whiteSpace: 'nowrap' }}>
                  {!tRes.pinned && (
                    <Button size="small" onClick={() => void run('Pinned', qrs().trust.pin(tRes.tcertId))}>
                      Pin
                    </Button>
                  )}
                  {tRes.pinned && (
                    <Button size="small" onClick={() => void run('Unpinned', qrs().trust.unpin(tRes.tcertId))}>
                      Unpin
                    </Button>
                  )}
                  {!tRes.isCa && (
                    <Button size="small" onClick={() => void run('Added as CA', qrs().trust.addCa(tRes.tcertId))}>
                      Make CA
                    </Button>
                  )}
                  {tRes.isCa && (
                    <Button size="small" onClick={() => void run('Removed CA', qrs().trust.removeCa(tRes.tcertId))}>
                      Remove CA
                    </Button>
                  )}
                  {!tRes.distrusted && (
                    <Button
                      size="small"
                      color="error"
                      onClick={() => void run('Distrusted', qrs().trust.distrust(tRes.tcertId))}
                    >
                      Distrust
                    </Button>
                  )}
                  {tRes.distrusted && (
                    <Button size="small" onClick={() => void run('Trusted again', qrs().trust.trustAgain(tRes.tcertId))}>
                      Trust again
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            ))}
            {received.length === 0 && (
              <TableRow>
                <TableCell colSpan={4}>
                  <Typography color="text.secondary">{t('trust.noCerts')}</Typography>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      {trust && trust.attestations.length > 0 && (
        <Card sx={{ mt: 2 }}>
          <CardContent>
            <Typography variant="h6" sx={{ mb: 1 }}>
              {t('trust.attestations')} ({trust.attestations.length})
            </Typography>
            {trust.attestations.map((a, i) => (
              <Box
                key={`${a.caTcertId}-${a.targetTcertId}-${i}`}
                sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}
              >
                <Typography variant="body2" color="text.secondary" sx={{ flexGrow: 1 }}>
                  {shortId(a.caTcertId)} → {shortId(a.targetTcertId)}
                  {a.claims && Object.keys(a.claims).length > 0 ? ` · ${JSON.stringify(a.claims)}` : ''}
                </Typography>
                {a.bytesB64 ? (
                  <ObjectActions
                    type="statement"
                    bytesB64={a.bytesB64}
                    fileName={a.statementId ?? a.targetTcertId}
                    qrTitle="Attestation QR"
                    showNotice={showNotice}
                  />
                ) : null}
              </Box>
            ))}
          </CardContent>
        </Card>
      )}

      <QRCodeDialog
        open={attestQr !== null}
        title="Statement QR"
        payload={attestQr ? buildQrPayload('statement', attestQr.bytesB64) : ''}
        hint={t('trust.statementQr')}
        onClose={() => setAttestQr(null)}
        showNotice={showNotice}
        onCopy={(text) => {
          void navigator.clipboard.writeText(text).then(() => showNotice('info', t('common.copied')));
        }}
      />
    </Box>
  );
}
