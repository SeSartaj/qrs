import { useState } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  IconButton,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import DnsIcon from '@mui/icons-material/Dns';
import type { TcertSummary } from '@shared/types';
import { qrs, safe } from '../api';

interface Props {
  tcert: TcertSummary;
  /** Called after an add/remove so the parent can reload the cert list (refresh endpoints). */
  onChanged: () => void;
  showNotice: (severity: 'success' | 'error' | 'info', text: string) => void;
}

/**
 * Per-TCert distribution endpoint manager.
 *
 * The signed `onlineEndpoint` is the fixed default; extra mirrors are stored
 * app-locally and synced to (fan-out). Endpoints are untrusted distribution
 * mirrors — every downloaded object is still verified cryptographically.
 */
export function EndpointManager({ tcert, onChanged, showNotice }: Props) {
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const signedDefault = tcert.onlineEndpoint ? tcert.onlineEndpoint.replace(/\/+$/, '') : undefined;
  const mirrors = (tcert.endpoints ?? []).filter((e) => e !== signedDefault);
  const effective = signedDefault ? [signedDefault, ...mirrors] : mirrors;

  const add = async (): Promise<void> => {
    const url = input.trim();
    if (!url || busy) return;
    setBusy(true);
    try {
      const res = await safe(qrs().endpoints.add(tcert.tcertId, url));
      if (!res.ok) {
        showNotice('error', `Add mirror failed: ${res.error}`);
        return;
      }
      setInput('');
      showNotice('success', `Mirror added: ${url}`);
      onChanged();
    } catch (e) {
      // e.g. stale preload without the endpoints API — surface it instead of
      // leaving the form stuck disabled.
      showNotice('error', `Add mirror failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  const remove = async (url: string): Promise<void> => {
    if (busy) return;
    setBusy(true);
    try {
      const res = await safe(qrs().endpoints.remove(tcert.tcertId, url));
      if (!res.ok) {
        showNotice('error', `Remove mirror failed: ${res.error}`);
        return;
      }
      showNotice('info', `Mirror removed: ${url}`);
      onChanged();
    } catch (e) {
      showNotice('error', `Remove mirror failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card sx={{ mb: 2 }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
          <DnsIcon fontSize="small" color="action" />
          <Typography variant="subtitle2">Distribution endpoints</Typography>
          <Typography variant="caption" color="text.secondary">
            (signed default + mirrors — servers are untrusted; everything is verified)
          </Typography>
        </Box>

        {effective.length === 0 && (
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            No endpoints configured. Add a mirror below to start distributing this certificate's data.
          </Typography>
        )}

        {effective.map((ep) => {
          const isDefault = ep === signedDefault;
          return (
            <Box key={ep} sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
              <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: 12, flexGrow: 1 }}>
                {ep}
              </Typography>
              <Chip
                size="small"
                color={isDefault ? 'primary' : 'default'}
                label={isDefault ? 'default' : 'mirror'}
              />
              {!isDefault && (
                <Tooltip title="Remove mirror">
                  <IconButton size="small" onClick={() => void remove(ep)} disabled={busy}>
                    <DeleteIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
              )}
            </Box>
          );
        })}

        <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
          <TextField
            size="small"
            fullWidth
            placeholder="https://another-server.example"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') void add();
            }}
            disabled={busy}
          />
          <Button
            variant="outlined"
            size="small"
            startIcon={<AddIcon />}
            onClick={() => void add()}
            disabled={busy || !input.trim()}
          >
            Add mirror
          </Button>
        </Box>
      </CardContent>
    </Card>
  );
}
