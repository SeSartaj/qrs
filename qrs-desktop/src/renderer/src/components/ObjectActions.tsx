import { useState } from 'react';
import { IconButton, Tooltip } from '@mui/material';
import QrCode2Icon from '@mui/icons-material/QrCode2';
import DataObjectIcon from '@mui/icons-material/DataObject';
import DownloadIcon from '@mui/icons-material/Download';
import type { TransferObjectType } from 'qrs-core';
import type { DecodedObject } from '@shared/types';
import { qrs, safe } from '../api';
import { QRCodeDialog, buildQrPayload } from './QRCodeDialog';
import { StructureDialog } from './StructureDialog';

const isDev = import.meta.env.DEV;

interface Props {
  type: TransferObjectType;
  bytesB64: string;
  qrTitle: string;
  qrHint?: string;
  /** Suggested `.qrs` file name (without extension). */
  fileName?: string;
  showNotice: (severity: 'success' | 'error' | 'info', text: string) => void;
}

/**
 * Row actions for a signed object: show its transfer QR code, export it as a
 * `.qrs` file and (in dev mode) inspect its plaintext and complete COSE structure.
 */
export function ObjectActions({ type, bytesB64, qrTitle, qrHint, fileName, showNotice }: Props) {
  const [qrOpen, setQrOpen] = useState(false);
  const [structure, setStructure] = useState<DecodedObject | null>(null);

  const payload = buildQrPayload(type, bytesB64);

  const inspect = async (): Promise<void> => {
    const res = await safe(qrs().objects.decode(bytesB64));
    if (!res.ok) {
      showNotice('error', res.error);
      return;
    }
    setStructure(res.value);
  };

  const exportQrs = async (): Promise<void> => {
    const res = await safe(qrs().objects.exportQrs({ type, bytesB64, suggestedName: fileName }));
    if (!res.ok) {
      showNotice('error', `Export failed: ${res.error}`);
      return;
    }
    if (!res.value.saved) {
      showNotice('info', 'Export cancelled');
      return;
    }
    showNotice('success', `Exported .qrs file: ${res.value.path ?? ''}`);
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
      {isDev && (
        <Tooltip title="Inspect structure (dev)">
          <IconButton size="small" onClick={() => void inspect()}>
            <DataObjectIcon />
          </IconButton>
        </Tooltip>
      )}
      <QRCodeDialog
        open={qrOpen}
        title={qrTitle}
        payload={payload}
        hint={qrHint}
        onClose={() => setQrOpen(false)}
        showNotice={showNotice}
        onCopy={(text) => {
          void navigator.clipboard.writeText(text).then(() => showNotice('info', 'Copied payload to clipboard'));
        }}
      />
      <StructureDialog
        open={structure !== null}
        title={structure ? `${structure.type} · ${structure.id ?? structure.algorithm}` : ''}
        json={structure ?? undefined}
        diagnostic={
          structure
            ? Object.entries(structure.wire.cborDiagnostic as Record<string, unknown>)
                .map(([name, dump]) => `-- ${name} --\n${String(dump)}`)
                .join('\n\n')
            : undefined
        }
        onClose={() => setStructure(null)}
      />
    </>
  );
}
