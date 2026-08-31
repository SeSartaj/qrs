import { useState } from 'react';
import { Alert, Button, Dialog, DialogActions, DialogContent, DialogTitle, TextField } from '@mui/material';
import type { TcertSummary } from '@shared/types';
import { qrs, safe } from '../api';

interface Props {
  tcert: TcertSummary;
  open: boolean;
  onClose: () => void;
  onChanged: () => void;
  showNotice: (severity: 'success' | 'error' | 'info', text: string) => void;
}

export function TcertPinDialog({ tcert, open, onClose, onChanged, showNotice }: Props) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [remove, setRemove] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const close = () => { setCurrent(''); setNext(''); setRemove(false); setError(null); onClose(); };
  const submit = async () => {
    setError(null);
    const result = remove
      ? await safe(qrs().certificates.removePin(tcert.tcertId, current))
      : tcert.hasPin
        ? await safe(qrs().certificates.changePin(tcert.tcertId, current, next))
        : await safe(qrs().certificates.setPin(tcert.tcertId, next));
    if (!result.ok) { setError(result.error); return; }
    showNotice('success', remove ? 'TCert PIN removed' : tcert.hasPin ? 'TCert PIN changed' : 'TCert PIN set');
    onChanged();
    close();
  };

  return (
    <Dialog open={open} onClose={close} fullWidth maxWidth="xs">
      <DialogTitle>{tcert.hasPin ? 'Manage TCert PIN' : 'Set TCert PIN'}</DialogTitle>
      <DialogContent>
        {tcert.hasPin && <TextField autoFocus fullWidth margin="dense" label="Current PIN" type="password" inputMode="numeric" value={current} onChange={(e) => setCurrent(e.target.value)} />}
        {!remove && <TextField autoFocus={!tcert.hasPin} fullWidth margin="dense" label={tcert.hasPin ? 'New PIN' : 'PIN'} type="password" inputMode="numeric" value={next} onChange={(e) => setNext(e.target.value)} helperText="Use 4 to 12 digits" />}
        {error && <Alert severity="error" sx={{ mt: 1 }}>{error}</Alert>}
      </DialogContent>
      <DialogActions>
        {tcert.hasPin && <Button color="error" onClick={() => { setRemove(true); setNext(''); }}>Remove PIN</Button>}
        {remove && <Button onClick={() => setRemove(false)}>Keep PIN</Button>}
        <Button onClick={close}>Cancel</Button>
        <Button variant="contained" onClick={() => void submit()}>{remove ? 'Remove' : 'Save'}</Button>
      </DialogActions>
    </Dialog>
  );
}
