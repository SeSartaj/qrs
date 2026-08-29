import { useCallback, useState } from 'react';
import { Box, Button, Chip, Typography } from '@mui/material';
import DownloadIcon from '@mui/icons-material/Download';
import ImageIcon from '@mui/icons-material/Image';
import DescriptionIcon from '@mui/icons-material/Description';
import type { AttachmentData } from '@shared/types';
import { qrs, safe } from '../api';

interface Props {
  /** Compact content hash signed into the SDoc attachment field. */
  reference: string | { hash: string; size?: number };
  /** MIME type declared by the signed TCert schema. */
  contentType: string;
  /** The issuing TCert's distribution mirrors (fallback when not cached locally). */
  onlineEndpoints?: string[];
}

function isImage(contentType: string): boolean {
  return contentType.startsWith('image/');
}

/** Human-readable size (e.g. "1.2 MB"). */
function fmtSize(bytes?: number): string {
  if (bytes === undefined) return '…';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Renders a raw attachment referenced by an SDoc. Fetching is OFFLINE-FIRST: it
 * loads only metadata (size + contentType), shows them, and downloads the file on
 * demand when the user clicks Download/Open — it never auto-downloads.
 */
export function AttachmentView({ reference, contentType, onlineEndpoints }: Props) {
  const id = typeof reference === 'string' ? reference : reference.hash;
  const signedSize = typeof reference === 'string' ? undefined : reference.size;
  const [status, setStatus] = useState<'ok' | 'missing' | 'error'>('ok');
  const [message, setMessage] = useState('');
  const [loadingContent, setLoadingContent] = useState(false);
  const [data, setData] = useState<AttachmentData | null>(null);

  /** Fetch the actual file bytes on demand. */
  const loadContent = useCallback(async (): Promise<AttachmentData | null> => {
    if (data) return data;
    setLoadingContent(true);
    try {
      const res = await safe(qrs().attachments.get({
        id,
        ...(signedSize === undefined ? {} : { size: signedSize }),
        contentType,
        onlineEndpoints,
        content: true,
      }));
      if (!res.ok) {
        setStatus('error');
        setMessage(res.error);
      } else if (!res.value) {
        setStatus('missing');
        setMessage('Attachment unavailable, corrupted, or not found on the server');
      } else {
        setData(res.value);
      }
      return res.ok ? res.value ?? null : null;
    } finally {
      setLoadingContent(false);
    }
  }, [id, signedSize, contentType, onlineEndpoints, data]);
  if (status === 'missing' || status === 'error') {
    return (
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <Chip size="small" color="warning" label={status === 'missing' ? 'unavailable' : 'error'} />
        <Typography variant="caption" color="text.secondary">{message}</Typography>
      </Box>
    );
  }

  // The hash is signed in the SDoc. File metadata is fetched from the server only when needed.
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
      <Chip
        size="small"
        icon={contentType === 'application/pdf' ? <DescriptionIcon /> : <ImageIcon />}
        label={`${contentType} · ${fmtSize(data?.size ?? signedSize)}`}
        variant="outlined"
      />
      <Button
        size="small"
        variant="outlined"
        startIcon={<DownloadIcon />}
        disabled={loadingContent}
        onClick={async () => {
          const d = await loadContent();
          if (!d?.contentB64) return;
          void safe(qrs().attachments.open({ id, bytesB64: d.contentB64, contentType: d.contentType }));
        }}
      >
        {loadingContent ? 'Loading…' : 'Open'}
      </Button>
      <Button
        size="small"
        variant="outlined"
        startIcon={<DownloadIcon />}
        disabled={loadingContent}
        onClick={async () => {
          const d = await loadContent();
          if (!d?.contentB64) return;
          await safe(qrs().attachments.save({ id, bytesB64: d.contentB64, contentType: d.contentType, defaultName: `${id}.${extOf(contentType)}` }));
        }}
      >
        Download
      </Button>
      {isImage(contentType) && data?.contentB64 ? (
        <img
          src={`data:${data.contentType};base64,${data.contentB64}`}
          alt={id.slice(0, 12)}
          style={{ maxWidth: 140, maxHeight: 100, borderRadius: 6, border: '1px solid rgba(128,128,128,0.3)' }}
        />
      ) : null}
    </Box>
  );
}

function extOf(contentType: string): string {
  const map: Record<string, string> = {
    'application/pdf': 'pdf',
    'image/png': 'png',
    'image/jpeg': 'jpg',
    'image/webp': 'webp',
    'text/plain': 'txt',
    'application/json': 'json',
  };
  return map[contentType] ?? 'bin';
}
