import { Box, MenuItem, TextField } from '@mui/material';
import type { FieldSchema } from '../lib/api';
import { FlexDateTimeInput } from './FlexDateTimeInput';
import { LocationFieldInput } from './LocationFieldInput';
import { FieldErrorBoundary } from './FieldErrorBoundary';

interface Props {
  field: FieldSchema;
  value: unknown;
  onChange: (value: unknown) => void;
  disabled?: boolean;
}

/**
 * Renders an input appropriate for a field type. Used at issuance time and shared
 * by all pages that need to collect field values.
 */
export function FieldValueInput({ field, value, onChange, disabled }: Props) {
  // A field with a declared default is auto-filled at signing time (e.g. a hidden
  // `issuedAt` datetime) — it is not shown in the form.
  if (field.default !== undefined) return null;
  switch (field.type) {
    case 'text': {
      const required = field.input_rules?.required === true;
      return (
        <TextField
          label={field.label}
          required={required}
          value={typeof value === 'string' ? value : ''}
          onChange={(e) => onChange(e.target.value)}
          fullWidth
          disabled={disabled}
          helperText={required ? 'required' : undefined}
          slotProps={{ htmlInput: { dir: 'auto' } }}
        />
      );
    }
    case 'textarea': {
      const required = field.input_rules?.required === true;
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
      const raw = field.input_rules?.options;
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
      const epochValue = typeof value === 'number'
        ? value
        : typeof value === 'string' && value.trim() !== ''
          ? Number(value)
          : undefined;
      return (
        <FieldErrorBoundary label={field.label}>
          <FlexDateTimeInput
            label={field.label}
            kind="datetimeEpoch"
            value={epochValue !== undefined && Number.isFinite(epochValue) ? epochValue : undefined}
            epoch
            onChange={(v) => onChange(v)}
            fullWidth
            disabled={disabled}
            helperText="Entered in your local time; stored as UTC epoch seconds."
          />
        </FieldErrorBoundary>
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
        />
      );
    case 'date':
      return (
        <FieldErrorBoundary label={field.label}>
          <FlexDateTimeInput
            label={field.label}
            kind="date"
            value={typeof value === 'string' ? value : undefined}
            onChange={(v) => onChange(typeof v === 'string' && v ? v : undefined)}
            fullWidth
          />
        </FieldErrorBoundary>
      );
    case 'datetime':
      return (
        <FieldErrorBoundary label={field.label}>
          <FlexDateTimeInput
            label={field.label}
            kind="datetime"
            value={typeof value === 'string' ? value : undefined}
            epoch={false}
            onChange={onChange}
            fullWidth
            disabled={disabled}
            helperText="Entered in your local time; stored as canonical UTC."
          />
        </FieldErrorBoundary>
      );
    case 'location': {
      return (
        <LocationFieldInput
          label={field.label}
          value={(value ?? {}) as { lat?: number; lon?: number }}
          onChange={onChange}
          disabled={disabled}
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
          helperText="Signed but not stored in the document"
        />
      );
  }
}
