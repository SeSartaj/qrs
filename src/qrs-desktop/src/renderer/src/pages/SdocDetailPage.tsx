import { useEffect, useState } from 'react';
import { Alert, Box, Button, Card, CardContent, Chip, Divider, IconButton, Tooltip, Typography } from '@mui/material';
import SyncIcon from '@mui/icons-material/Sync';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import { useTranslation } from 'react-i18next';
import type { DocumentSummary } from '@shared/types';
import { qrs, safe, shortId, formatDate } from '../api';
import { ObjectActions } from '../components/ObjectActions';
import { InlineQRCode } from '../components/InlineQRCode';
import { OverflowMenu } from '../components/OverflowMenu';

type ShowNotice = (severity: 'success' | 'error' | 'info', text: string) => void;

/** Render a single decoded field value for the detail page. */
function renderDetailValue(v: NonNullable<DocumentSummary['values']>[number]): { text: string; color?: string } {
  const val = v.value;
  if (val === undefined || val === null || val === '') return { text: '—' };
  if (typeof val === 'string' && v.type === 'attachment') {
    return { text: `${v.contentType ?? 'file'} · ${val.slice(0, 12)}…` };
  }
  if (v.type === 'selectv2') {
    const idx = typeof val === 'number' ? val : -1;
    const raw = v.options;
    const options = Array.isArray(raw)
      ? raw.map((o) => (typeof o === 'string' ? { label: o, value: o } : (o as { label: string; value: string; color?: string })))
      : [];
    const opt = idx >= 0 && idx < options.length ? options[idx] : undefined;
    return { text: opt?.label ?? String(val), color: opt?.color };
  }
  if (v.type === 'datetimeEpoch' && typeof val === 'number') {
    return { text: formatDate(val) };
  }
  if (v.type === 'datetime' && typeof val === 'string') {
    const timestamp = Date.parse(val);
    if (Number.isFinite(timestamp)) return { text: formatDate(Math.floor(timestamp / 1000)) };
  }
  if (v.type === 'date' && typeof val === 'string') {
    const timestamp = Date.parse(`${val}T00:00:00Z`);
    if (Number.isFinite(timestamp)) return { text: formatDate(Math.floor(timestamp / 1000)).replace(/ \d{2}:\d{2} UTC$/, '') };
  }
  if (typeof val === 'object') {
    if ('lat' in val && 'lon' in val) {
      const loc = val as { lat: number; lon: number };
      return { text: `${loc.lat.toFixed(5)}, ${loc.lon.toFixed(5)}` };
    }
    return { text: JSON.stringify(val) };
  }
  return { text: String(val) };
}

interface Props {
  sdocId: string;
  onBack: () => void;
  onVerify: (bytesB64: string) => void;
  showNotice: ShowNotice;
  signerKeyId: string;
}

/** A dedicated details page for a single SDoc. */
export function SdocDetailPage({ sdocId, onBack, onVerify, showNotice, signerKeyId }: Props) {
  const { t } = useTranslation();
  const [doc, setDoc] = useState<DocumentSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pendingIds, setPendingIds] = useState<Set<string>>(new Set());
  const [syncing, setSyncing] = useState(false);

  useEffect(() => {
    void (async () => {
      const res = await safe(qrs().documents.get(sdocId));
      if (res.ok) setDoc(res.value);
      else setError(res.error);
      const queueRes = await safe(qrs().attachments.queue());
      if (queueRes.ok && res.ok && res.value) {
        const attachmentIds = new Set((res.value.values ?? []).filter((v) => v.type === 'attachment').map((v) => String(v.value)));
        setPendingIds(new Set(queueRes.value.queue.filter((item) => item.kind === 'attachment' && attachmentIds.has(item.id)).map((item) => item.id)));
      }
    })();
  }, [sdocId]);

  const copy = async (text: string): Promise<void> => {
    await navigator.clipboard.writeText(text);
    showNotice('info', t('common.copied'));
  };

  const refreshDocument = async (): Promise<void> => {
    const res = await safe(qrs().documents.get(sdocId));
    if (res.ok && res.value) setDoc(res.value);
  };

  if (error) {
    return (
      <Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
          <Tooltip title={t('documents.backToCerts')}>
            <IconButton onClick={onBack}>
              <ArrowBackIcon />
            </IconButton>
          </Tooltip>
          <Typography variant="h5">SDoc</Typography>
        </Box>
        <Alert severity="error">{error}</Alert>
      </Box>
    );
  }

  if (!doc) {
    return (
      <Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
          <Tooltip title={t('documents.backToCerts')}>
            <IconButton onClick={onBack}>
              <ArrowBackIcon />
            </IconButton>
          </Tooltip>
          <Typography variant="h5">SDoc</Typography>
        </Box>
        <Typography color="text.secondary">Loading…</Typography>
      </Box>
    );
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Tooltip title={t('documents.backToCerts')}>
            <IconButton onClick={onBack}>
              <ArrowBackIcon />
            </IconButton>
          </Tooltip>
          <Typography variant="h5">SDoc {shortId(doc.sdocId)}</Typography>
          <Chip size="small" label={doc.blocked ? 'Blocked' : 'Active'} color={doc.blocked ? 'error' : 'success'} />
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <ObjectActions type="sdoc" bytesB64={doc.bytesB64} fileName={doc.sdocId} qrTitle="SDoc QR" showNotice={showNotice} />
          <Button size="small" startIcon={<ContentCopyIcon />} onClick={() => void copy(doc.bytesB64)}>
            {t('common.copy')}
          </Button>
          <Button size="small" startIcon={<VerifiedUserIcon />} onClick={() => onVerify(doc.bytesB64)}>
            {t('common.verify')}
          </Button>
          <OverflowMenu actions={[{ label: doc.blocked ? 'Unblock SDoc' : 'Block SDoc', color: doc.blocked ? 'inherit' : 'error', onClick: async () => {
            if (!window.confirm(`Block SDoc ${shortId(doc.sdocId)}?`)) return;
            const input = { signerKeyId, targetSdocId: doc.sdocId };
            const res = await safe(doc.blocked ? qrs().revocation.unblockSdoc(input) : qrs().revocation.blockSdoc(input));
            if (res.ok) { showNotice('success', doc.blocked ? 'SDoc unblocked' : 'SDoc blocked'); await refreshDocument(); } else showNotice('error', `Action failed: ${res.error}`);
          }}]} />
        </Box>
      </Box>

      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
            <Box>
              <Typography variant="body2" color="text.secondary">
                {t('documents.issued')}
              </Typography>
              <Typography variant="subtitle1">{formatDate(doc.issuedAt)}</Typography>
            </Box>
            <Box>
              <Typography variant="body2" color="text.secondary">
                Size
              </Typography>
              <Typography variant="subtitle1">{doc.sizeBytes} bytes</Typography>
            </Box>
            <Box>
              <Typography variant="body2" color="text.secondary">
                SDoc ID
              </Typography>
              <Typography variant="subtitle1" sx={{ fontFamily: 'monospace', fontSize: 13 }}>
                {doc.sdocId}
              </Typography>
            </Box>
          </Box>
        </CardContent>
      </Card>

      <Card sx={{ mb: 2 }}><CardContent><InlineQRCode type="sdoc" bytesB64={doc.bytesB64} showNotice={showNotice} /></CardContent></Card>
      {pendingIds.size > 0 && <Button startIcon={<SyncIcon />} disabled={syncing} onClick={async () => {
        setSyncing(true);
        const res = await safe(qrs().attachments.sync());
        setSyncing(false);
        if (res.ok) { const queueRes = await safe(qrs().attachments.queue()); if (queueRes.ok) setPendingIds(new Set(queueRes.value.queue.filter((item) => item.kind === 'attachment').map((item) => item.id))); showNotice('success', `Uploaded ${res.value.uploaded} attachment(s)`); }
        else showNotice('error', `Sync failed: ${res.error}`);
      }}>Sync queued attachments ({pendingIds.size})</Button>}

      <Typography variant="h6" sx={{ mb: 1 }}>
        {t('documents.fields')}
      </Typography>
      <Card>
        <CardContent>
          {(doc.values ?? []).length === 0 ? (
            <Typography color="text.secondary">No stored values.</Typography>
          ) : (
            (doc.values ?? []).map((v, i) => {
              const { text, color } = renderDetailValue(v);
              const attachmentPending = v.type === 'attachment' && typeof v.value === 'string' && pendingIds.has(v.value);
              return (
                <Box key={`${v.name}-${i}`}>
                  {i > 0 && <Divider sx={{ my: 1 }} />}
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, py: 0.5 }}>
                    <Typography variant="body2" color="text.secondary" sx={{ flex: 1 }}>
                      {v.label}
                    </Typography>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flex: 2 }}>
                      {color && (
                        <Box
                          sx={{
                            width: 12,
                            height: 12,
                            borderRadius: '50%',
                            backgroundColor: color,
                            flexShrink: 0,
                          }}
                        />
                      )}
                      <Typography variant="body2" sx={{ fontWeight: 600 }}>
                        {text}
                      </Typography>
                      {v.type === 'attachment' && (
                        attachmentPending
                          ? <Button size="small" startIcon={<SyncIcon />} disabled={syncing} onClick={async () => { setSyncing(true); const res = await safe(qrs().attachments.sync()); setSyncing(false); if (!res.ok) showNotice('error', `Upload failed: ${res.error}`); else { const q = await safe(qrs().attachments.queue()); if (q.ok) setPendingIds(new Set(q.value.queue.filter((item) => item.kind === 'attachment').map((item) => item.id))); showNotice('success', 'Attachment uploaded'); } }}>Sync</Button>
                          : <Typography variant="caption" color="success.main">Uploaded</Typography>
                      )}
                    </Box>
                  </Box>
                </Box>
              );
            })
          )}
        </CardContent>
      </Card>
    </Box>
  );
}
