import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Dialog, DialogActions, DialogContent, DialogTitle, TextField } from '@mui/material';
import type { TcertSummary } from '@shared/types';
import { qrs, safe } from '../api';

export function TcertPinPrompt({ tcert, open, onCancel, onAuthorized }: { tcert: TcertSummary; open: boolean; onCancel: () => void; onAuthorized: (pin: string) => void }) {
  const [pin, setPin] = useState('');
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setError(null);
      window.setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [open]);

  const cancel = () => { setPin(''); setError(null); onCancel(); };
  const submit = async () => {
    const result = await safe(qrs().certificates.verifyPin(tcert.tcertId, pin));
    if (!result.ok) { setPin(''); setError(result.error); window.setTimeout(() => inputRef.current?.focus(), 0); return; }
    if (!result.value) { setPin(''); setError('Incorrect TCert PIN.'); window.setTimeout(() => inputRef.current?.focus(), 0); return; }
    setError(null); onAuthorized(pin);
  };

  return (
    <Dialog open={open} onClose={cancel} fullWidth maxWidth="xs">
      <DialogTitle>Enter TCert PIN</DialogTitle>
      <DialogContent>
        <TextField
          inputRef={inputRef}
          fullWidth
          margin="dense"
          label={`PIN for ${tcert.name}`}
          type="password"
          inputMode="numeric"
          value={pin}
          onChange={(e) => setPin(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); void submit(); } }}
        />
        {error && <Alert severity="error" sx={{ mt: 1 }}>{error}</Alert>}
      </DialogContent>
      <DialogActions>
        <Button onClick={cancel}>Cancel</Button>
        <Button variant="contained" onClick={() => void submit()}>Continue</Button>
      </DialogActions>
    </Dialog>
  );
}
