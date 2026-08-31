import { Box, MenuItem, TextField } from '@mui/material';
import type { FieldSchema } from 'qrs-core';
import { FlexDateTimeInput } from './FlexDateTimeInput';
import { AttachmentFieldInput } from './AttachmentFieldInput';
import { LocationFieldInput } from './LocationFieldInput';

interface Props {
  field: FieldSchema;
  value: unknown;
  onChange: (value: unknown) => void;
  disabled?: boolean;
  /** Upload context for attachment fields (issuing TCert keyId + endpoints). */
  attachmentContext?: { keyId: string; tcertId: string; onlineEndpoints?: string[] };
  showNotice?: (severity: 'success' | 'error' | 'info', text: string) => void;
  onAttachmentUploadState?: (fieldName: string, uploaded: boolean) => void;
  onAttachmentUploadBusy?: (fieldName: string, uploading: boolean) => void;
  autoFocus?: boolean;
}

/**
 * Renders an input appropriate for a field type. Used at issuance time and shared
 * by all pages that need to collect field values.
 */
export function FieldValueInput({ field, value, onChange, disabled, attachmentContext, showNotice, onAttachmentUploadState, onAttachmentUploadBusy, autoFocus }: Props) {
  // A field with a declared default is auto-filled at signing time (e.g. a hidden
  // `issuedAt` datetime) — it is not shown in the form.
  if (field.default !== undefined) return null;
  switch (field.type) {
    case 'text': {
      const required = field.inputRules?.required === true;
      return (
        <TextField
          label={field.label}
          required={required}
          value={typeof value === 'string' ? value : ''}
          onChange={(e) => onChange(e.target.value)}
          fullWidth
          disabled={disabled}
          autoFocus={autoFocus}
          helperText={required ? 'required' : undefined}
          slotProps={{ htmlInput: { dir: 'auto' } }}
        />
      );
    }
    case 'textarea': {
      const required = field.inputRules?.required === true;
      return (
        <TextField
          label={field.label}
          required={required}
          multiline
          minRows={3}
          value={typeof value === 'string' ? value : ''}
          onChange={(e) => onChange(e.target.value)}
          fullWidth
          disabled={disabled}
          autoFocus={autoFocus}
          helperText={required ? 'required' : undefined}
          slotProps={{ htmlInput: { dir: 'auto' } }}
        />
      );
    }
    case 'select': {
      const options = [...new Set(field.options ?? [])];
      return (
        <TextField
          select
          label={field.label}
          value={typeof value === 'string' ? value : ''}
          onChange={(e) => onChange(e.target.value)}
          fullWidth
          disabled={disabled}
          autoFocus={autoFocus}
          helperText={options.length > 0 ? `Allowed: ${options.join(', ')}` : 'free text'}
        >
          {options.map((o) => (
            <MenuItem key={o} value={o}>
              {o}
            </MenuItem>
          ))}
        </TextField>
      );
    }
    case 'selectv2': {
      // Options are { label, value, color? }; the stored value is the option index.
      const raw = field.inputRules?.options;
      const options: { label: string; value: string; color?: string }[] = Array.isArray(raw)
        ? raw.map((o) => (typeof o === 'string' ? { label: o, value: o } : (o as { label: string; value: string; color?: string })))
        : (field.options ?? []).map((o) => ({ label: o, value: o }));
      const idx = typeof value === 'number' ? value : -1;
      return (
        <TextField
          select
          label={field.label}
          value={idx >= 0 && idx < options.length ? idx : ''}
          onChange={(e) => onChange(Number(e.target.value))}
          fullWidth
          disabled={disabled}
          autoFocus={autoFocus}
        >
          {options.map((o, i) => (
            <MenuItem key={i} value={i}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                {o.color && (
                  <Box
                    sx={{
                      width: 12,
                      height: 12,
                      borderRadius: '50%',
                      backgroundColor: o.color,
                      flexShrink: 0,
                    }}
                  />
                )}
                {o.label}
              </Box>
            </MenuItem>
          ))}
        </TextField>
      );
    }
    case 'datetimeEpoch': {
      // Stored as integer UTC epoch seconds. The input shows local time in the
      // user's chosen calendar; only the stored value is UTC.
      return (
        <FlexDateTimeInput
          label={field.label}
          kind="datetimeEpoch"
          value={typeof value === 'number' ? value : undefined}
          epoch
          onChange={(v) => onChange(v)}
          fullWidth
          disabled={disabled}
          autoFocus={autoFocus}
          helperText="Entered in your local time; stored as UTC epoch seconds."
        />
      );
    }
    case 'number':
      return (
        <TextField
          label={field.label}
          type="number"
          value={typeof value === 'number' ? value : ''}
          onChange={(e) => {
            const raw = e.target.value.trim();
            onChange(raw === '' ? undefined : Number(raw));
          }}
          fullWidth
          disabled={disabled}
          autoFocus={autoFocus}
        />
      );
    case 'date':
      return (
        <FlexDateTimeInput
          label={field.label}
          kind="date"
          value={typeof value === 'string' ? value : undefined}
          onChange={(v) => onChange(typeof v === 'string' && v ? v : undefined)}
          fullWidth
          autoFocus={autoFocus}
        />
      );
    case 'datetime':
      return (
        <FlexDateTimeInput
          label={field.label}
          kind="datetime"
          value={typeof value === 'string' ? value : undefined}
          epoch={false}
          onChange={onChange}
          fullWidth
          autoFocus={autoFocus}
          disabled={disabled}
          helperText="Entered in your local time; stored as canonical UTC."
        />
      );
    case 'location': {
      return (
        <LocationFieldInput
          label={field.label}
          value={(value ?? {}) as { lat?: number; lon?: number }}
          onChange={onChange}
          disabled={disabled}
          autoFocus={autoFocus}
        />
      );
    }
    case 'secretInput':
      return (
        <TextField
          label={field.label}
          type="password"
          value={typeof value === 'string' ? value : ''}
          onChange={(e) => onChange(e.target.value)}
          fullWidth
          disabled={disabled}
          autoFocus={autoFocus}
          helperText="Signed but not stored in the document"
        />
      );
    case 'attachment':
      return (
        <AttachmentFieldInput
          field={field}
          value={value}
          onChange={onChange}
          attachmentContext={attachmentContext}
          showNotice={showNotice}
          onAttachmentUploadState={onAttachmentUploadState}
          onAttachmentUploadBusy={onAttachmentUploadBusy}
          disabled={disabled}
        />
      );
  }
}
