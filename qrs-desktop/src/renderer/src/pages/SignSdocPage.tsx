import { useEffect, useRef, useState } from 'react';
import { Alert, Box, Button, Card, CardContent, Grid, IconButton, Tooltip, Typography, TextField } from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import { useTranslation } from 'react-i18next';
import type { DocumentSummary, TcertSummary } from '@shared/types';
import { qrs, safe, shortId } from '../api';
import { FieldValueInput } from '../components/FieldValueInput';
import { ObjectActions } from '../components/ObjectActions';

type ShowNotice = (severity: 'success' | 'error' | 'info', text: string) => void;

/** A value is "missing" when absent, empty, or a location without coordinates. */
function isMissing(v: unknown): boolean {
  if (v === undefined || v === null || v === '') return true;
  if (typeof v === 'object' && v !== null && 'lat' in v) {
    const loc = v as { lat?: number; lon?: number };
    return !Number.isFinite(loc.lat ?? NaN) || !Number.isFinite(loc.lon ?? NaN);
  }
  return false;
}

interface Props {
  tcert: TcertSummary;
  authorizedPin?: string;
  pinAuthorized?: boolean;
  onBack: () => void;
  onIssued: (doc: DocumentSummary) => void;
  showNotice: ShowNotice;
}

/** A dedicated page for signing a new SDoc under a specific TCert. */
export function SignSdocPage({ tcert, authorizedPin, pinAuthorized = false, onBack, onIssued, showNotice }: Props) {
  const { t } = useTranslation();
  const [values, setValues] = useState<Record<string, unknown>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<DocumentSummary | null>(null);
  const [uploadedAttachments, setUploadedAttachments] = useState<Record<string, boolean>>({});
  const [uploadingAttachments, setUploadingAttachments] = useState<Record<string, boolean>>({});
  const [pin, setPin] = useState(authorizedPin ?? '');
  const [pinRequired, setPinRequired] = useState(false);
  const pinInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      onBack();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onBack]);

  const issue = async (): Promise<void> => {
    setError(null);
    setResult(null);
    const signFields = tcert.fields.filter((f) => f.default === undefined);
    const missing = signFields.filter((f) => f.inputRules?.required === true && isMissing(values[f.name]));
    if (missing.length > 0) {
      setError(`${t('documents.missingRequired')}: ${missing.map((f) => f.label).join(', ')}`);
      return;
    }
    const notUploaded = signFields.filter(
      (f) => f.type === 'attachment' && f.inputRules?.required === true && !uploadedAttachments[f.name]
    );
    if (notUploaded.length > 0) {
      setError(`Required attachment must be uploaded before signing: ${notUploaded.map((f) => f.label).join(', ')}`);
      return;
    }
    setBusy(true);
    const res = await safe(qrs().documents.issue({ tcertId: tcert.tcertId, values, pin: tcert.hasPin ? pin : undefined }));
    setBusy(false);
    if (!res.ok) {
      if (tcert.hasPin && res.error.toLowerCase().includes('incorrect tcert pin')) {
        setPin('');
        setPinRequired(true);
        window.setTimeout(() => pinInputRef.current?.focus(), 0);
        setError('Your PIN authorization expired. Enter the PIN again to continue.');
        return;
      }
      setError(res.error);
      return;
    }
    setResult(res.value);
    setValues({});
    setPin('');
    setPinRequired(false);
    showNotice('success', `${t('documents.issued')}: ${shortId(res.value.sdocId)}`);
    onIssued(res.value);
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <Tooltip title={`${t('documents.backToCerts')} (Esc)`}>
          <IconButton onClick={onBack}>
            <ArrowBackIcon />
          </IconButton>
        </Tooltip>
        <Typography variant="h5">
          {t('documents.signNew')} — {tcert.name}
        </Typography>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
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

      <Card>
        <CardContent>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>
            {t('documents.fields')}
          </Typography>
          {tcert.hasPin && (!pinAuthorized || pinRequired) && <TextField inputRef={pinInputRef} label="TCert PIN" type="password" inputMode="numeric" value={pin} onChange={(e) => setPin(e.target.value)} fullWidth size="small" sx={{ mb: 2 }} />}
          <Grid container spacing={2}>
            {tcert.fields
              .filter((f) => f.default === undefined)
              .map((f, i) => (
                <Grid size={{ xs: 12, sm: 6 }} key={`${f.name}-${i}`}>
                  <FieldValueInput
                    field={f}
                    autoFocus={i === 0}
                    value={values[f.name]}
                    onChange={(v) => setValues((prev) => ({ ...prev, [f.name]: v }))}
                    attachmentContext={{
                      keyId: tcert.keyId,
                      tcertId: tcert.tcertId,
                      onlineEndpoints: tcert.endpoints ?? [],
                    }}
                    showNotice={showNotice}
                    onAttachmentUploadState={(name, uploaded) => setUploadedAttachments((prev) => ({ ...prev, [name]: uploaded }))}
                    onAttachmentUploadBusy={(name, uploading) => setUploadingAttachments((prev) => ({ ...prev, [name]: uploading }))}
                  />
                </Grid>
              ))}
          </Grid>
          <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
            <Button variant="contained" onClick={() => void issue()} disabled={busy || Object.values(uploadingAttachments).some(Boolean)}>
              {busy ? t('documents.issuing') : t('documents.sign')}
            </Button>
            <Button variant="text" onClick={onBack}>
              {t('common.cancel')}
            </Button>
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
}
