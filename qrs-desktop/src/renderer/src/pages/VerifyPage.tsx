import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Divider,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableRow,
  TextField,
  Typography,
} from '@mui/material';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import { useTranslation } from 'react-i18next';
import type { DocumentSummary, VerifyDetail } from '@shared/types';
import { qrs, safe, shortId } from '../api';
import { AttachmentView } from '../components/AttachmentView';
import { ObjectActions } from '../components/ObjectActions';

type ShowNotice = (severity: 'success' | 'error' | 'info', text: string) => void;

const stateColor = (state: string): 'success' | 'error' | 'warning' | 'default' => {
  if (state === 'valid' || state === 'satisfied') return 'success';
  if (state === 'invalid' || state === 'denied') return 'error';
  if (state === 'cannotVerify' || state === 'missing') return 'warning';
  return 'default';
};

function formatValue(v: unknown): string {
  if (v === undefined || v === null) return '—';
  if (typeof v === 'object') {
    const loc = v as { lat?: number; lon?: number };
    if (typeof loc.lat === 'number' && typeof loc.lon === 'number') return `${loc.lat}, ${loc.lon}`;
    return JSON.stringify(v);
  }
  return String(v);
}

/** selectv2 stores the option index; verification results should show its label. */
function formatDocumentValue(field: { type: string; value: unknown; options?: unknown }): string {
  if (field.type === 'selectv2' && typeof field.value === 'number' && Array.isArray(field.options)) {
    const option = field.options[field.value] as unknown;
    if (typeof option === 'string') return option;
    if (typeof option === 'object' && option !== null && 'label' in option) {
      const label = (option as { label?: unknown }).label;
      if (typeof label === 'string') return label;
    }
  }
  return formatValue(field.value);
}

interface VerifyPageProps {
  initialBytesB64?: string;
  onConsumed?: () => void;
  showNotice?: ShowNotice;
}

export function VerifyPage({ initialBytesB64, onConsumed, showNotice }: VerifyPageProps) {
  const { t } = useTranslation();
  const [bytesB64, setBytesB64] = useState('');
  const [docs, setDocs] = useState<DocumentSummary[]>([]);
  const [selectedDoc, setSelectedDoc] = useState('');
  const [detail, setDetail] = useState<VerifyDetail | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      const res = await safe(qrs().documents.list());
      if (res.ok) setDocs(res.value);
    })();
  }, []);

  // Preload an SDoc passed from another tab.
  useEffect(() => {
    if (initialBytesB64) {
      setBytesB64(initialBytesB64);
      setDetail(null);
      onConsumed?.();
    }
  }, [initialBytesB64, onConsumed]);

  useEffect(() => {
    if (selectedDoc) {
      const doc = docs.find((d) => d.sdocId === selectedDoc);
      if (doc) setBytesB64(doc.bytesB64);
    }
  }, [selectedDoc, docs]);

  // Screenshot/CI helper: when the main process sets window.__qrsAutoVerify,
  // load the first issued document and verify it automatically.
  const autoVerifyDone = useRef(false);
  useEffect(() => {
    if (autoVerifyDone.current) return;
    const auto = (window as unknown as { __qrsAutoVerify?: boolean }).__qrsAutoVerify;
    if (auto && docs.length > 0) {
      autoVerifyDone.current = true;
      setSelectedDoc(docs[0].sdocId);
    }
  }, [docs]);
  useEffect(() => {
    if (autoVerifyDone.current && bytesB64 && !detail && !busy) void verify();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bytesB64, detail, busy]);

  const verify = async (): Promise<void> => {
    if (!bytesB64.trim()) {
      setError('Paste an SDoc (base64url) first.');
      return;
    }
    setError(null);
    setDetail(null);
    setBusy(true);
    const res = await safe(qrs().verification.verify({ bytesB64: bytesB64.trim() }));
    setBusy(false);
    if (!res.ok) {
      setError(res.error);
      return;
    }
    setDetail(res.value);
  };

  const result = detail?.result ?? null;

  const breakdown = useMemo(() => {
    if (!result) return [];
    return [
      { key: 'cryptographic', state: result.cryptographic },
      { key: 'tcert', state: result.tcert },
      { key: 'trust', state: result.trust },
      { key: 'revocation', state: result.revocation },
      { key: 'schema', state: result.schema },
    ];
  }, [result]);

  const notify = showNotice ?? (() => undefined);

  return (
    <Box>
      <Typography variant="h5" sx={{ mb: 3 }}>
        {t('verify.title')}
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Card sx={{ mb: 2 }}>
        <CardContent>
          {docs.length > 0 && (
            <FormControl fullWidth size="small" sx={{ mb: 2 }}>
              <InputLabel>{t('verify.loadIssued')}</InputLabel>
              <Select value={selectedDoc} label={t('verify.loadIssued')} onChange={(e) => setSelectedDoc(e.target.value)}>
                {docs.map((d) => (
                  <MenuItem key={d.sdocId} value={d.sdocId}>
                    {d.documentName ?? shortId(d.tcertId)} · {shortId(d.sdocId)}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          )}
          <TextField
            label="SDoc (base64url)"
            multiline
            minRows={3}
            maxRows={6}
            fullWidth
            value={bytesB64}
            onChange={(e) => setBytesB64(e.target.value)}
            placeholder={t('verify.sdocPlaceholder')}
            sx={{ mb: 2, fontFamily: 'monospace' }}
          />
          <Button variant="contained" size="large" startIcon={<VerifiedUserIcon />} onClick={verify} disabled={busy}>
            {busy ? t('verify.verifying') : t('verify.verifyOffline')}
          </Button>
        </CardContent>
      </Card>

      {detail && result && (
        <Card>
          <CardContent>
            {/* Centered CA / issuer / document header */}
            <Box sx={{ textAlign: 'center', mb: 2 }}>
              {/* CA name — with a trusted tick when the document is CA-issued */}
              {detail.caName && (
                <Box sx={{ display: 'inline-flex', alignItems: 'center', gap: 0.5, mb: 0.25 }}>
                  {result.trust === 'valid' && <CheckCircleIcon color="success" fontSize="small" />}
                  <Typography variant="subtitle2" color="secondary">
                    {detail.caName}
                  </Typography>
                </Box>
              )}
              {/* Issuer name */}
              <Typography variant="h6" sx={{ fontWeight: 600 }}>
                {detail.issuerName ?? '—'}
              </Typography>
              {/* Document name */}
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                {detail.documentName ?? '—'}
              </Typography>
              <Box sx={{ display: 'inline-flex', alignItems: 'center', gap: 1, mt: 1 }}>
                <Chip
                  label={result.overall.toUpperCase()}
                  color={stateColor(result.overall)}
                  variant="filled"
                  sx={{ fontWeight: 700 }}
                />
                {detail.bytesB64 && (
                  <ObjectActions
                    type="sdoc"
                    bytesB64={detail.bytesB64}
                    qrTitle="SDoc QR"
                    qrHint={t('verify.qrHint')}
                    showNotice={notify}
                  />
                )}
              </Box>
            </Box>

            {result.message && (
              <Typography variant="body2" color="text.secondary" align="center" sx={{ mb: 1 }}>
                {result.message}
              </Typography>
            )}

            <Divider sx={{ my: 2 }} />

            {/* Actual values (labels, not machine names) */}
            <Typography variant="h6" sx={{ mb: 1 }}>
              {t('verify.actualValues')}
            </Typography>
            {detail.values && detail.values.length > 0 ? (
              <TableContainer component={Box} sx={{ mb: 2 }}>
                <Table size="small">
                  <TableBody>
                    {detail.values.map((v, i) => (
                      <TableRow key={`${v.name}-${i}`} hover>
                        <TableCell sx={{ width: '40%', color: 'text.secondary' }}>{v.label}</TableCell>
                        <TableCell>
                          {v.type === 'attachment' && typeof v.value === 'object' && v.value !== null ? (
                            <AttachmentView
                              reference={v.value as { hash: string; size: number }}
                              contentType={v.contentType ?? 'application/octet-stream'}
                              onlineEndpoints={detail.onlineEndpoints}
                            />
                          ) : (
                            formatDocumentValue(v)
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            ) : (
              <Typography variant="body2" color="text.secondary">
                {t('verify.noValues')}
              </Typography>
            )}

            <Divider sx={{ my: 2 }} />

            <Typography variant="h6" sx={{ mb: 1 }}>
              {t('verify.result')}
            </Typography>
            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mt: 1 }}>
              {breakdown.map((b) => (
                <Chip key={b.key} size="small" label={`${b.key}: ${b.state}`} color={stateColor(b.state)} variant="outlined" />
              ))}
              <Chip size="small" label={`context: ${result.context}`} color={stateColor(result.context)} variant="outlined" />
            </Box>

            {result.fields.length > 0 && (
              <Box sx={{ mt: 2 }}>
                <Typography variant="subtitle2" sx={{ mb: 0.5 }}>
                  {t('verify.fields')}
                </Typography>
                {result.fields.map((f, i) => (
                  <Box key={`${f.name}-${i}`} sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                    <Chip size="small" label={f.state} color={stateColor(f.state)} variant="outlined" />
                    <Typography variant="body2">{f.label ?? f.name}</Typography>
                    {f.message && (
                      <Typography variant="caption" color="text.secondary">
                        — {f.message}
                      </Typography>
                    )}
                  </Box>
                ))}
              </Box>
            )}

            {result.warnings.length > 0 && (
              <Alert severity="warning" sx={{ mt: 2 }}>
                {result.warnings.join('; ')}
              </Alert>
            )}
          </CardContent>
        </Card>
      )}
    </Box>
  );
}
