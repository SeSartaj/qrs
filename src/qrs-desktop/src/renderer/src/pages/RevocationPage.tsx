import { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  FormControl,
  Grid,
  InputLabel,
  MenuItem,
  Select,
  TextField,
  Typography,
} from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { DocumentSummary, KeySummary, RevocationState, StatementResultDto, TcertSummary } from '@shared/types';
import { qrs, safe, shortId, formatDate } from '../api';
import { QRCodeDialog, buildQrPayload } from '../components/QRCodeDialog';

type ShowNotice = (severity: 'success' | 'error' | 'info', text: string) => void;

export function RevocationPage({ showNotice }: { showNotice: ShowNotice }) {
  const { t } = useTranslation();
  const [keys, setKeys] = useState<KeySummary[]>([]);
  const [tcerts, setTcerts] = useState<TcertSummary[]>([]);
  const [docs, setDocs] = useState<DocumentSummary[]>([]);
  const [state, setState] = useState<RevocationState | null>(null);
  const [statementQr, setStatementQr] = useState<StatementResultDto | null>(null);

  // Revoke TCert
  const [signerKey, setSignerKey] = useState('');
  const [targetTcert, setTargetTcert] = useState('');
  const [revType, setRevType] = useState<'prospective' | 'retrospective'>('retrospective');
  const [revTcertReason, setRevTcertReason] = useState('');

  // Revoke key
  const [signerKey2, setSignerKey2] = useState('');
  const [targetKey, setTargetKey] = useState('');
  const [revKeyReason, setRevKeyReason] = useState('');

  // Block SDoc
  const [signerKey3, setSignerKey3] = useState('');
  const [targetSdoc, setTargetSdoc] = useState('');
  const [blockReason, setBlockReason] = useState('');

  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    const [k, t, d, s] = await Promise.all([
      safe(qrs().keys.list()),
      safe(qrs().certificates.list()),
      safe(qrs().documents.list()),
      safe(qrs().revocation.state()),
    ]);
    if (k.ok) setKeys(k.value);
    if (t.ok) setTcerts(t.value);
    if (d.ok) setDocs(d.value);
    if (s.ok) setState(s.value);
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const applyResult = (res: { ok: true; value: StatementResultDto } | { ok: false; error: string }): void => {
    if (!res.ok) {
      setError(res.error);
      return;
    }
    setStatementQr(res.value);
    showNotice('success', t('revocation.statementIssued'));
    if (res.value.published && res.value.endpoints && res.value.endpoints.length > 0) {
      showNotice('success', `Published to ${res.value.endpoints.join(', ')}`);
    } else {
      showNotice('info', 'Not published — no online_endpoint on the signer certificate');
    }
    void reload();
  };

  const revokeTcert = async (): Promise<void> => {
    setError(null);
    if (!signerKey || !targetTcert) {
      setError('Select a signer key and a target certificate.');
      return;
    }
    const res = await safe(
      qrs().revocation.revokeTcert({ signerKeyId: signerKey, targetTcertId: targetTcert, type: revType, reason: revTcertReason || undefined })
    );
    applyResult(res);
  };

  const revokeKey = async (): Promise<void> => {
    setError(null);
    if (!signerKey2 || !targetKey) {
      setError('Select a signer key and a target key.');
      return;
    }
    const res = await safe(qrs().revocation.revokeKey({ signerKeyId: signerKey2, targetKeyId: targetKey, reason: revKeyReason || undefined }));
    applyResult(res);
  };

  const blockSdoc = async (unblock: boolean): Promise<void> => {
    setError(null);
    if (!signerKey3 || !targetSdoc) {
      setError('Select a signer key and a target document.');
      return;
    }
    const input = { signerKeyId: signerKey3, targetSdocId: targetSdoc, reason: blockReason || undefined };
    const res = await safe(unblock ? qrs().revocation.unblockSdoc(input) : qrs().revocation.blockSdoc(input));
    applyResult(res);
  };

  return (
    <Box>
      <Typography variant="h5" sx={{ mb: 3 }}>
        {t('revocation.title')}
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Grid container spacing={2} sx={{ mb: 2 }}>
        <Grid size={{ xs: 12, md: 4 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 1 }}>
                {t('revocation.revokeTcert')}
              </Typography>
              <FormControl fullWidth size="small" sx={{ mb: 1 }}>
                <InputLabel>{t('revocation.signerKey')}</InputLabel>
                <Select value={signerKey} label={t('revocation.signerKey')} onChange={(e) => setSignerKey(e.target.value)}>
                  {keys.map((k) => (
                    <MenuItem key={k.keyId} value={k.keyId}>
                      {shortId(k.keyId)} ({k.algorithm})
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              <FormControl fullWidth size="small" sx={{ mb: 1 }}>
                <InputLabel>{t('revocation.targetTcert')}</InputLabel>
                <Select value={targetTcert} label={t('revocation.targetTcert')} onChange={(e) => setTargetTcert(e.target.value)}>
                  {tcerts.map((t) => (
                    <MenuItem key={t.tcertId} value={t.tcertId}>
                      {t.name} ({shortId(t.tcertId)})
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              <FormControl fullWidth size="small" sx={{ mb: 1 }}>
                <InputLabel>{t('revocation.type')}</InputLabel>
                <Select value={revType} label={t('revocation.type')} onChange={(e) => setRevType(e.target.value as 'prospective' | 'retrospective')}>
                  <MenuItem value="prospective">{t('revocation.prospective')}</MenuItem>
                  <MenuItem value="retrospective">{t('revocation.retrospective')}</MenuItem>
                </Select>
              </FormControl>
              <TextField label={t('revocation.reason')} size="small" fullWidth value={revTcertReason} onChange={(e) => setRevTcertReason(e.target.value)} sx={{ mb: 1 }} />
              <Button variant="contained" color="error" onClick={() => void revokeTcert()} fullWidth>
                {t('revocation.revoke')}
              </Button>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12, md: 4 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 1 }}>
                {t('revocation.revokeKey')}
              </Typography>
              <FormControl fullWidth size="small" sx={{ mb: 1 }}>
                <InputLabel>{t('revocation.signerKey')}</InputLabel>
                <Select value={signerKey2} label={t('revocation.signerKey')} onChange={(e) => setSignerKey2(e.target.value)}>
                  {keys.map((k) => (
                    <MenuItem key={k.keyId} value={k.keyId}>
                      {shortId(k.keyId)}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              <FormControl fullWidth size="small" sx={{ mb: 1 }}>
                <InputLabel>{t('revocation.targetKey')}</InputLabel>
                <Select value={targetKey} label={t('revocation.targetKey')} onChange={(e) => setTargetKey(e.target.value)}>
                  {keys.map((k) => (
                    <MenuItem key={k.keyId} value={k.keyId}>
                      {shortId(k.keyId)} ({k.algorithm})
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              <TextField label={t('revocation.reason')} size="small" fullWidth value={revKeyReason} onChange={(e) => setRevKeyReason(e.target.value)} sx={{ mb: 1 }} />
              <Button variant="contained" color="error" onClick={() => void revokeKey()} fullWidth>
                {t('revocation.revoke')}
              </Button>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12, md: 4 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 1 }}>
                {t('revocation.blockSdoc')}
              </Typography>
              <FormControl fullWidth size="small" sx={{ mb: 1 }}>
                <InputLabel>{t('revocation.signerKey')}</InputLabel>
                <Select value={signerKey3} label={t('revocation.signerKey')} onChange={(e) => setSignerKey3(e.target.value)}>
                  {keys.map((k) => (
                    <MenuItem key={k.keyId} value={k.keyId}>
                      {shortId(k.keyId)}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              <FormControl fullWidth size="small" sx={{ mb: 1 }}>
                <InputLabel>{t('revocation.targetSdoc')}</InputLabel>
                <Select value={targetSdoc} label={t('revocation.targetSdoc')} onChange={(e) => setTargetSdoc(e.target.value)}>
                  {docs.map((d) => (
                    <MenuItem key={d.sdocId} value={d.sdocId}>
                      {d.documentName ?? shortId(d.tcertId)} · {shortId(d.sdocId)}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              <TextField label={t('revocation.reason')} size="small" fullWidth value={blockReason} onChange={(e) => setBlockReason(e.target.value)} sx={{ mb: 1 }} />
              <Box sx={{ display: 'flex', gap: 1 }}>
                <Button variant="contained" color="error" onClick={() => void blockSdoc(false)} fullWidth>
                  {t('revocation.block')}
                </Button>
                <Button variant="outlined" onClick={() => void blockSdoc(true)} fullWidth>
                  {t('revocation.unblock')}
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {state && (
        <Grid container spacing={2}>
          <Grid size={{ xs: 12, md: 4 }}>
            <Card>
              <CardContent>
                <Typography variant="h6">{t('revocation.revokedTcerts')}</Typography>
                {state.revokedTcerts.map((r) => (
                  <Typography key={r.tcertId} variant="body2" color="text.secondary">
                    {shortId(r.tcertId)} · {r.type} · {formatDate(r.issuedAt)}
                  </Typography>
                ))}
                {state.revokedTcerts.length === 0 && (
                  <Typography variant="body2" color="text.secondary">
                    {t('common.none')}
                  </Typography>
                )}
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 12, md: 4 }}>
            <Card>
              <CardContent>
                <Typography variant="h6">{t('revocation.revokedKeys')}</Typography>
                {state.revokedKeys.map((r) => (
                  <Typography key={r.keyId} variant="body2" color="text.secondary">
                    {shortId(r.keyId)} · {formatDate(r.issuedAt)}
                  </Typography>
                ))}
                {state.revokedKeys.length === 0 && (
                  <Typography variant="body2" color="text.secondary">
                    {t('common.none')}
                  </Typography>
                )}
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 12, md: 4 }}>
            <Card>
              <CardContent>
                <Typography variant="h6">{t('revocation.blockedSdocs')}</Typography>
                {state.blockedSdocs.map((r) => (
                  <Typography key={r.sdocId} variant="body2" color="text.secondary">
                    {shortId(r.sdocId)} · {formatDate(r.issuedAt)}
                  </Typography>
                ))}
                {state.blockedSdocs.length === 0 && (
                  <Typography variant="body2" color="text.secondary">
                    {t('common.none')}
                  </Typography>
                )}
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      <QRCodeDialog
        open={statementQr !== null}
        title="Statement QR"
        payload={statementQr ? buildQrPayload('statement', statementQr.bytesB64) : ''}
        hint={t('revocation.statementQr')}
        onClose={() => setStatementQr(null)}
        showNotice={showNotice}
        onCopy={(text) => {
          void navigator.clipboard.writeText(text).then(() => showNotice('info', t('common.copied')));
        }}
      />
    </Box>
  );
}
