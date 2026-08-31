import { useEffect, useState } from 'react';
import { Box, TextField, Typography } from '@mui/material';
import { formatLocationPair, parseLocationPair } from '../lib/locationFormat';

/**
 * Reusable location input.
 *
 * Supports two entry styles:
 *   - a single "lat, lon" field that accepts a direct paste from Google Maps
 *     (e.g. `34.51958749194178, 69.17472990319257`) and commits as soon as the
 *     pair is valid;
 *   - separate Latitude / Longitude number fields, kept in sync with the pair.
 */
export interface LocationValue {
  lat?: number;
  lon?: number;
}

interface Props {
  label: string;
  value?: LocationValue;
  onChange: (value: LocationValue) => void;
  disabled?: boolean;
  helper?: string;
  autoFocus?: boolean;
}

export function LocationFieldInput({ label, value, onChange, disabled, helper, autoFocus }: Props) {
  const [pairText, setPairText] = useState<string>(formatLocationPair(value?.lat, value?.lon));

  // Sync the pair field when the value changes from outside (e.g. clearing).
  useEffect(() => {
    setPairText(formatLocationPair(value?.lat, value?.lon));
  }, [value]);

  const handlePair = (text: string): void => {
    setPairText(text);
    if (text.trim() === '') {
      onChange({});
      return;
    }
    const parsed = parseLocationPair(text);
    if (parsed) onChange(parsed);
  };

  const num = (v?: number): string => (typeof v === 'number' ? String(v) : '');

  return (
    <Box>
      <Typography variant="caption" color="text.secondary">
        {label} — latitude, longitude
        {helper ? ` · ${helper}` : ''}
      </Typography>
      <TextField
        label="lat, lon (paste from Google Maps)"
        placeholder="34.51958749194178, 69.17472990319257"
        value={pairText}
        onChange={(e) => handlePair(e.target.value)}
        fullWidth
        disabled={disabled}
        autoFocus={autoFocus}
        size="small"
        sx={{ mt: 0.5 }}
      />
      <Box sx={{ display: 'flex', gap: 1, mt: 0.5 }}>
        <TextField
          label="Latitude"
          type="number"
          value={num(value?.lat)}
          onChange={(e) => onChange({ lat: parseFloat(e.target.value), lon: value?.lon })}
          fullWidth
          disabled={disabled}
        />
        <TextField
          label="Longitude"
          type="number"
          value={num(value?.lon)}
          onChange={(e) => onChange({ lat: value?.lat, lon: parseFloat(e.target.value) })}
          fullWidth
          disabled={disabled}
        />
      </Box>
    </Box>
  );
}
