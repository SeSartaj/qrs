import { useState } from 'react';
import { Alert, Box, Button, Card, CardContent, Grid, IconButton, Tooltip, Typography } from '@mui/material';
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
  onBack: () => void;
  onIssued: (doc: DocumentSummary) => void;
  showNotice: ShowNotice;
}

/** A dedicated page for signing a new SDoc under a specific TCert. */
export function SignSdocPage({ tcert, onBack, onIssued, showNotice }: Props) {
  const { t } = useTranslation();
  const [values, setValues] = useState<Record<string, unknown>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<DocumentSummary | null>(null);
  const [uploadedAttachments, setUploadedAttachments] = useState<Record<string, boolean>>({});
  const [uploadingAttachments, setUploadingAttachments] = useState<Record<string, boolean>>({});

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
    const res = await safe(qrs().documents.issue({ tcertId: tcert.tcertId, values }));
    setBusy(false);
    if (!res.ok) {
      setError(res.error);
      return;
    }
    setResult(res.value);
    setValues({});
    showNotice('success', `${t('documents.issued')}: ${shortId(res.value.sdocId)}`);
    onIssued(res.value);
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <Tooltip title={t('documents.backToCerts')}>
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
          <Grid container spacing={2}>
            {tcert.fields
              .filter((f) => f.default === undefined)
              .map((f, i) => (
                <Grid size={{ xs: 12, sm: 6 }} key={`${f.name}-${i}`}>
                  <FieldValueInput
                    field={f}
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
