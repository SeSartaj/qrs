import { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  TextField,
  Typography,
} from '@mui/material';
import { api, type ManagedTcert } from '../lib/api';

export function CaPage() {
  const [tcerts, setTcerts] = useState<ManagedTcert[]>([]);
  const [caId, setCaId] = useState<number | ''>('');
  const [targetTcertId, setTargetTcertId] = useState('');
  const [targetSdocId, setTargetSdocId] = useState('');
  const [reason, setReason] = useState('');
  const [result, setResult] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    api
      .listTcerts()
      .then((list) => setTcerts(list.filter((t) => t.is_ca)))
      .catch((e) => setError(e.message));
  }, []);

  const run = async (fn: () => Promise<unknown>, label: string) => {
    setError('');
    setResult('');
    try {
      const res = await fn();
      setResult(`${label}: ${JSON.stringify(res)}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : `${label} failed`);
    }
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        CA operations
      </Typography>
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      {result && <Alert severity="success" sx={{ mb: 2 }}>{result}</Alert>}
      <Card>
        <CardContent>
          <FormControl fullWidth sx={{ mb: 2 }}>
            <InputLabel>CA TCert</InputLabel>
            <Select value={caId} onChange={(e) => setCaId(e.target.value as number)} label="CA TCert">
              {tcerts.map((t) => (
                <MenuItem key={t.id} value={t.id}>
                  {t.name} ({t.tcert_id})
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <TextField
            label="Target TCert ID"
            value={targetTcertId}
            onChange={(e) => setTargetTcertId(e.target.value)}
            fullWidth
            sx={{ mb: 2 }}
          />
          <TextField
            label="Target SDoc ID"
            value={targetSdocId}
            onChange={(e) => setTargetSdocId(e.target.value)}
            fullWidth
            sx={{ mb: 2 }}
          />
          <TextField
            label="Reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            fullWidth
            sx={{ mb: 2 }}
          />
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            <Button
              variant="contained"
              disabled={caId === '' || !targetTcertId}
              onClick={() => run(() => api.attest(caId as number, targetTcertId), 'Attest')}
            >
              Attest
            </Button>
            <Button
              variant="contained"
              color="warning"
              disabled={caId === '' || !targetTcertId}
              onClick={() => run(() => api.revoke(caId as number, targetTcertId, reason), 'Revoke')}
            >
              Revoke TCert
            </Button>
            <Button
              variant="contained"
              color="error"
              disabled={!targetSdocId}
              onClick={() => run(() => api.blockSdoc(targetSdocId, reason), 'Block SDoc')}
            >
              Block SDoc
            </Button>
            <Button
              variant="outlined"
              color="success"
              disabled={!targetSdocId}
              onClick={() => run(() => api.unblockSdoc(targetSdocId, reason), 'Unblock SDoc')}
            >
              Unblock SDoc
            </Button>
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
}