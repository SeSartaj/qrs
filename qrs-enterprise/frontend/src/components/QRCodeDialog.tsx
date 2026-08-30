import { useRef } from 'react';
import {
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Typography,
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import FileDownloadIcon from '@mui/icons-material/FileDownload';
import { QRCodeCanvas } from 'qrcode.react';

/** Build the scannable transfer payload for a signed object's base64url bytes. */
export function buildQrPayload(type: string, bytesB64: string): string {
  return `qrs://v1/${type}/${bytesB64}`;
}

type ShowNotice = (severity: 'success' | 'error' | 'info', text: string) => void;

interface Props {
  open: boolean;
  title: string;
  /** The QR payload string (e.g. `qrs://v1/tcert/…`). */
  payload: string;
  hint?: string;
  onClose: () => void;
  showNotice?: ShowNotice;
}

function slug(name: string): string {
  return (
    (name || 'qrs-qr')
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'qrs-qr'
  );
}

export function QRCodeDialog({ open, title, payload, hint, onClose, showNotice }: Props) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  const toPngDataUrl = (): string | null => {
    const canvas = canvasRef.current;
    return canvas ? canvas.toDataURL('image/png') : null;
  };

  const copyImage = async (): Promise<void> => {
    const dataUrl = toPngDataUrl();
    if (!dataUrl) return;
    try {
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
    const a = document.createElement('a');
    a.href = dataUrl;
    a.download = `${slug(title)}.png`;
    a.click();
    showNotice?.('success', 'QR PNG downloaded');
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1 }}>
          <Box
            sx={{
              p: 2,
              borderRadius: 2,
              border: '2px solid',
              borderColor: 'success.main',
              bgcolor: 'background.paper',
              boxShadow: 3,
            }}
          >
            <QRCodeCanvas ref={canvasRef} value={payload} size={880} style={{ width: 260, height: 260 }} level="Q" marginSize={4} />
          </Box>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', justifyContent: 'center' }}>
            <Button size="small" startIcon={<ContentCopyIcon />} onClick={() => void copyImage()}>
              Copy image
            </Button>
            <Button size="small" startIcon={<FileDownloadIcon />} onClick={() => void downloadPng()}>
              Download PNG
            </Button>
            <Button
              size="small"
              onClick={() =>
                void navigator.clipboard.writeText(payload).then(() => showNotice?.('info', 'Payload copied'))
              }
            >
              Copy payload
            </Button>
          </Box>
          {hint && (
            <Typography variant="caption" color="text.secondary">
              {hint}
            </Typography>
          )}
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}