import { useState } from 'react';
import { Box, Button, Chip, Typography } from '@mui/material';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import { attachmentContentType, type FieldSchema } from 'qrs-core';
import type { AttachmentSubmitResult } from '@shared/types';
import { bytesToBase64Url, qrs, safe } from '../api';

interface Props {
  field: FieldSchema;
  value: unknown;
  onChange: (value: unknown) => void;
  /** The issuing TCert's key + distribution endpoints to upload to (fan-out). */
  attachmentContext?: { keyId: string; tcertId: string; onlineEndpoints?: string[] };
  showNotice?: (severity: 'success' | 'error' | 'info', text: string) => void;
  onAttachmentUploadState?: (fieldName: string, uploaded: boolean) => void;
  onAttachmentUploadBusy?: (fieldName: string, uploading: boolean) => void;
  disabled?: boolean;
}

/**
 * Attachment field: a file input. The raw file bytes go to the main process,
 * which stores it locally and uploads it to the distribution mirrors. The MIME
 * type is fixed by this field's signed TCert schema and cannot be changed while
 * signing a document.
 */
export function AttachmentFieldInput({ field, value, onChange, attachmentContext, showNotice, onAttachmentUploadState, onAttachmentUploadBusy, disabled }: Props) {
  const [fileName, setFileName] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<AttachmentSubmitResult | null>(null);
  const contentType = attachmentContentType(field);
  const ref = (value as { hash?: unknown } | null | undefined) ?? null;
  const hash = typeof value === 'string' ? value : typeof ref?.hash === 'string' ? ref.hash : undefined;

  const onFile = async (file: File | null): Promise<void> => {
    if (!file || disabled) return;
    onAttachmentUploadState?.(field.name, false);
    onAttachmentUploadBusy?.(field.name, true);
    setBusy(true);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const acceptedType = contentType.toLowerCase();
      const selectedType = file.type.toLowerCase();
      const matchesType =
        acceptedType === 'application/octet-stream' ||
        (acceptedType.endsWith('/*')
          ? selectedType.startsWith(acceptedType.slice(0, -1))
          : selectedType === acceptedType);
      if (!matchesType) {
        showNotice?.('error', `This field only accepts ${contentType}; selected file is ${file.type || 'an unknown type'}`);
        return;
      }

      if (!attachmentContext) {
        showNotice?.('error', 'Issuing TCert has no key to sign attachments with');
        return;
      }

      const submit = await safe(
        qrs().attachments.submit({
          keyId: attachmentContext.keyId,
          tcertId: attachmentContext.tcertId,
          fieldName: field.name,
          onlineEndpoints: attachmentContext.onlineEndpoints ?? [],
          bytesB64: bytesToBase64Url(bytes),
        })
      );
      if (!submit.ok) {
        showNotice?.('error', `Upload failed: ${submit.error}`);
        return;
      }
      const res = submit.value;
      onAttachmentUploadState?.(field.name, !res.queued && !res.error);
      setFileName(file.name);
      setResult(res);
      if (res.error) {
        showNotice?.(
          'error',
          `Server rejected the attachment: ${res.error}${res.queued ? ' The file was kept locally and will be retried.' : ''}`
        );
      }
      onChange(res.hash); // SDoc stores only the content hash
    } finally {
      setBusy(false);
      onAttachmentUploadBusy?.(field.name, false);
    }
  };

  return (
    <Box>
      <Typography variant="caption" color="text.secondary">
        {field.label}
      </Typography>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5 }}>
        <Chip size="small" label={contentType} variant="outlined" />
        <Button
          component="label"
          variant="outlined"
          size="small"
          startIcon={<CloudUploadIcon />}
          disabled={busy || disabled}
        >
          {busy ? 'Uploading…' : fileName ?? 'Choose file'}
          <input
            type="file"
            accept={contentType === 'application/octet-stream' ? undefined : contentType}
            hidden
            onChange={(e) => void onFile(e.target.files?.[0] ?? null)}
          />
        </Button>
      </Box>
      {result && (
        <Typography variant="caption" display="block" color="text.secondary" sx={{ mt: 0.5 }}>
          {fileName} · {result.error ? `server rejected: ${result.error}` : result.queued ? 'stored locally — will sync when online' : 'uploaded to server'}
        </Typography>
      )}
      <Typography variant="caption" display="block" color="text.secondary" sx={{ mt: 0.5 }}>
        hash: {hash ? `${hash.slice(0, 12)}…` : '—'}
      </Typography>
    </Box>
  );
}
