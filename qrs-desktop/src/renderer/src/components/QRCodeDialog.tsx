import { useRef } from 'react';
import { Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, Typography } from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import FileDownloadIcon from '@mui/icons-material/FileDownload';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import { QRCodeCanvas } from 'qrcode.react';
import { encodeTransferPayload, type TransferObjectType } from 'qrs-core';
import { qrs, safe } from '../api';

/** Build the scannable transfer payload for a signed object's base64url bytes. */
export function buildQrPayload(type: TransferObjectType, bytesB64: string): string {
  return encodeTransferPayload(type, bytesB64);
}

type ShowNotice = (severity: 'success' | 'error' | 'info', text: string) => void;

interface Props {
  open: boolean;
  title: string;
  /** The QR payload string (e.g. `qrs://v1/tcert/…`). */
  payload: string;
  hint?: string;
  onClose: () => void;
  onCopy?: (text: string) => void;
  showNotice?: ShowNotice;
}

/** Slugify a title into a safe base file name for the PNG export. */
function slug(name: string): string {
  return (
    (name || 'qrs-qr')
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'qrs-qr'
  );
}

export function QRCodeDialog({ open, title, payload, hint, onClose, onCopy, showNotice }: Props) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  const toPngDataUrl = (): string | null => {
    const canvas = canvasRef.current;
    return canvas ? canvas.toDataURL('image/png') : null;
  };

  const copyImage = async (): Promise<void> => {
    const dataUrl = toPngDataUrl();
    if (!dataUrl) return;
    try {
      // Do not fetch the data URL: Electron can block `data:` fetches in the
      // renderer. Decode the canvas result directly into a Blob instead.
      const [header, encoded] = dataUrl.split(',', 2);
      if (!header || encoded === undefined) throw new Error('invalid PNG data URL');
      const binary = atob(encoded);
      const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
      const mime = header.match(/^data:([^;]+);base64$/)?.[1] ?? 'image/png';
      const blob = new Blob([bytes], { type: mime });
      await navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })]);
      showNotice?.('success', 'QR image copied to clipboard');
    } catch (error) {
      showNotice?.('error', `Could not copy image: ${error instanceof Error ? error.message : 'clipboard unavailable'}`);
    }
  };

  const downloadPng = async (): Promise<void> => {
    const dataUrl = toPngDataUrl();
    if (!dataUrl) return;
    const res = await safe(qrs().objects.saveQrPng({ dataUrl, suggestedName: slug(title) }));
    if (!res.ok) {
      showNotice?.('error', `Download failed: ${res.error}`);
      return;
    }
    if (!res.value.saved) {
      showNotice?.('info', 'Download cancelled');
      return;
    }
    showNotice?.('success', `Saved PNG: ${res.value.path ?? ''}`);
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1.5 }}>
          {/* Secure ring: white rounded card with a green verified border + check tick */}
          <Box sx={{ position: 'relative' }}>
            <Box
              sx={{
                p: 2.5,
                bgcolor: '#ffffff',
                borderRadius: 3,
                border: '3px solid',
                borderColor: 'success.main',
                boxShadow: '0 0 0 6px rgba(46,160,67,0.15)',
              }}
            >
              <QRCodeCanvas
                ref={canvasRef}
                value={payload}
                // Render the export canvas at 4x resolution, then downscale it
                // only for display so copied/downloaded PNGs stay sharp.
                size={880}
                level="M"
                marginSize={4}
                bgColor="#ffffff"
                fgColor="#000000"
                style={{ width: 220, height: 220 }}
              />
            </Box>
            <Box
              sx={{
                position: 'absolute',
                top: -14,
                right: -14,
                bgcolor: 'success.main',
                color: '#fff',
                borderRadius: '50%',
                width: 30,
                height: 30,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: 2,
              }}
            >
              <CheckCircleIcon fontSize="small" />
            </Box>
          </Box>
          <Typography variant="caption" color="success.main" sx={{ fontWeight: 600 }}>
            Signed &amp; verified
          </Typography>
          <Typography variant="caption" color="text.secondary" align="center">
            {hint ??
              'Scan with the mobile app — it will import this object and follow the standard protocol steps.'}
          </Typography>
          <Typography
            variant="caption"
            sx={{
              fontFamily: 'monospace',
              wordBreak: 'break-all',
              whiteSpace: 'pre-wrap',
              textAlign: 'left',
              width: '100%',
              maxHeight: 180,
              overflow: 'auto',
              p: 1,
              border: 1,
              borderColor: 'divider',
              borderRadius: 1,
              color: 'text.secondary',
            }}
          >
            {payload}
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', justifyContent: 'center' }}>
            <Button size="small" variant="outlined" startIcon={<ContentCopyIcon />} onClick={() => void copyImage()}>
              Copy image
            </Button>
            <Button size="small" variant="outlined" startIcon={<FileDownloadIcon />} onClick={() => void downloadPng()}>
              Download PNG
            </Button>
            {onCopy && (
              <Button size="small" variant="text" onClick={() => onCopy(payload)}>
                Copy payload
              </Button>
            )}
          </Box>
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}
