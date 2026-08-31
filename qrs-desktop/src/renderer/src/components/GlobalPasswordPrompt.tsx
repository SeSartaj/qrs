import { useState } from 'react';
import { Alert, Button, Dialog, DialogActions, DialogContent, DialogTitle, TextField, Typography } from '@mui/material';
import { qrs, safe } from '../api';

export function GlobalPasswordPrompt({ open, onUnlocked }: { open: boolean; onUnlocked: () => void }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);

  const unlock = async () => {
    setError(null);
    const result = await safe(qrs().keys.unlock(password));
    if (!result.ok) { setError(result.error); return; }
    setPassword('');
    onUnlocked();
  };

  return (
    <Dialog open={open} fullWidth maxWidth="xs">
      <DialogTitle>Unlock private keys</DialogTitle>
      <DialogContent>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          Enter the password protecting this desktop app’s private keys.
        </Typography>
        <TextField autoFocus fullWidth margin="dense" label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') void unlock(); }} />
        {error && <Alert severity="error" sx={{ mt: 1 }}>{error}</Alert>}
      </DialogContent>
      <DialogActions>
        <Button variant="contained" onClick={() => void unlock()}>Unlock</Button>
      </DialogActions>
    </Dialog>
  );
}
