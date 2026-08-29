import { useEffect, useState } from 'react';
import {
  Alert,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  TextField,
  Typography,
} from '@mui/material';
import type { ContextRequest } from '@shared/types';
import { qrs } from '../api';
import { LocationFieldInput } from './LocationFieldInput';

/**
 * Hosts the input dialogs the main process asks for during verification
 * (location / secret). It is the renderer half of the context provider.
 */
export function ContextDialogHost() {
  const [request, setRequest] = useState<ContextRequest | null>(null);
  const [location, setLocation] = useState<{ lat?: number; lon?: number }>({});
  const [secret, setSecret] = useState('');
  const [locationError, setLocationError] = useState<string | null>(null);

  useEffect(() => {
    return qrs().onContextRequest((req) => {
      setRequest(req);
      setLocation({});
      setSecret('');
      setLocationError(null);
    });
  }, []);

  const reply = (value: unknown): void => {
    if (request) qrs().replyContext({ requestId: request.requestId, value });
    setRequest(null);
  };

  const submit = (): void => {
    if (!request) return;
    if (request.kind === 'location') {
      const la = location.lat;
      const lo = location.lon;
      if (
        typeof la !== 'number' ||
        typeof lo !== 'number' ||
        !Number.isFinite(la) ||
        !Number.isFinite(lo)
      ) {
        setLocationError('Enter a valid location — paste "lat, lon" from Google Maps or fill both fields.');
        return;
      }
      reply({ lat: la, lon: lo });
    } else {
      reply(secret);
    }
  };

  if (!request) return null;

  return (
    <Dialog open onClose={() => reply(null)} fullWidth maxWidth="xs">
      <DialogTitle>{request.kind === 'location' ? 'Confirm location' : `Enter ${request.label}`}</DialogTitle>
      <DialogContent>
        {request.kind === 'location' ? (
          <>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              The document is bound to a geographic location. Enter the current position so the
              stored coordinates can be compared.
            </Typography>
            <LocationFieldInput
              label="Current position"
              value={location}
              onChange={setLocation}
              helper="paste from Google Maps or fill both fields"
            />
            {locationError && (
              <Alert severity="warning" sx={{ mt: 1 }}>
                {locationError}
              </Alert>
            )}
          </>
        ) : (
          <TextField
            label={request.label}
            type="password"
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            fullWidth
            autoFocus
            sx={{ mt: 1 }}
          />
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={() => reply(null)}>Cancel</Button>
        <Button variant="contained" onClick={submit}>
          Submit
        </Button>
      </DialogActions>
    </Dialog>
  );
}
