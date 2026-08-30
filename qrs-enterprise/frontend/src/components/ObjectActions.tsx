import { useState } from 'react';
import { IconButton, Tooltip } from '@mui/material';
import QrCode2Icon from '@mui/icons-material/QrCode2';
import DownloadIcon from '@mui/icons-material/Download';
import { QRCodeDialog, buildQrPayload } from './QRCodeDialog';

interface Props {
  type: string;
  bytesB64: string;
  qrTitle: string;
  qrHint?: string;
  /** Suggested `.qrs` file name (without extension). */
  fileName?: string;
  showNotice: (severity: 'success' | 'error' | 'info', text: string) => void;
}

/**
 * Row actions for a signed object: show its transfer QR code and export it as a
 * `.qrs` file. Adapted from the qrs-desktop `ObjectActions` component.
 */
export function ObjectActions({ type, bytesB64, qrTitle, qrHint, fileName, showNotice }: Props) {
  const [qrOpen, setQrOpen] = useState(false);
  const payload = buildQrPayload(type, bytesB64);

  const exportQrs = async (): Promise<void> => {
    const blob = new Blob([payload], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${fileName ?? 'object'}.qrs`;
    a.click();
    URL.revokeObjectURL(url);
    showNotice('success', `Exported .qrs file: ${fileName ?? 'object'}.qrs`);
  };

  return (
    <>
      <Tooltip title="Export .qrs file">
        <IconButton size="small" onClick={() => void exportQrs()}>
          <DownloadIcon />
        </IconButton>
      </Tooltip>
      <Tooltip title="QR code">
        <IconButton size="small" onClick={() => setQrOpen(true)}>
          <QrCode2Icon />
        </IconButton>
      </Tooltip>
      <QRCodeDialog
        open={qrOpen}
        title={qrTitle}
        payload={payload}
        hint={qrHint}
        onClose={() => setQrOpen(false)}
        showNotice={showNotice}
      />
    </>
  );
}