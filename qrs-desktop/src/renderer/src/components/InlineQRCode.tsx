import { useRef } from 'react';
import { Box, Button } from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import FileDownloadIcon from '@mui/icons-material/FileDownload';
import { QRCodeCanvas } from 'qrcode.react';
import { qrs, safe } from '../api';
import { buildQrPayload } from './QRCodeDialog';
import type { TransferObjectType } from 'qrs-core';

type ErrorCorrectionLevel = 'L' | 'M' | 'Q' | 'H';

interface Props {
  type: TransferObjectType;
  bytesB64: string;
  showNotice: (severity: 'success' | 'error' | 'info', text: string) => void;
  /** QR error correction; Q is a good balance for screen sharing and printing. */
  level?: ErrorCorrectionLevel;
  /** Logical canvas size in pixels before CSS display scaling. */
  size?: number;
}

/** Inline high-resolution QR with copy, PNG download, and payload actions. */
export function InlineQRCode({ type, bytesB64, showNotice, level = 'Q', size = 880 }: Props) {
  const ref = useRef<HTMLCanvasElement | null>(null);
  const payload = buildQrPayload(type, bytesB64);
  const copyImage = async (): Promise<void> => {
    const canvas = ref.current;
    if (!canvas) return;
    const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, 'image/png'));
    if (blob) await navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })]);
    showNotice('success', 'QR image copied');
  };
  const download = async (): Promise<void> => {
    const canvas = ref.current;
    if (!canvas) return;
    const res = await safe(qrs().objects.saveQrPng({ dataUrl: canvas.toDataURL('image/png'), suggestedName: type }));
    showNotice(res.ok && res.value.saved ? 'success' : 'info', res.ok && res.value.saved ? 'QR PNG saved' : 'Download cancelled');
  };
  return <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1 }}>
    <QRCodeCanvas ref={ref} value={payload} size={size} style={{ width: 260, height: 260 }} level={level} marginSize={4} />
    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', justifyContent: 'center' }}>
      <Button size="small" startIcon={<ContentCopyIcon />} onClick={() => void copyImage()}>Copy image</Button>
      <Button size="small" startIcon={<FileDownloadIcon />} onClick={() => void download()}>Download PNG</Button>
      <Button size="small" onClick={() => void navigator.clipboard.writeText(payload).then(() => showNotice('info', 'Payload copied'))}>Copy payload</Button>
    </Box>
  </Box>;
}
