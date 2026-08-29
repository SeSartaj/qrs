import { useEffect, useState } from 'react';
import { Alert, Box, Button, Card, CardContent, List, ListItem, ListItemText, Typography } from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import LockOpenIcon from '@mui/icons-material/LockOpen';
import type { TcertSummary } from '@shared/types';
import type { PageId } from '../components/Layout';
import { qrs, safe } from '../api';

export function ArchivePage({ onNavigate }: { onNavigate: (page: PageId) => void }) {
  const [certs, setCerts] = useState<TcertSummary[]>([]);
  const reload = async (): Promise<void> => { const [c, config] = await Promise.all([safe(qrs().certificates.list()), safe(qrs().config.get())]); if (c.ok && config.ok) setCerts(c.value.filter((x) => (config.value.archivedTcerts ?? []).includes(x.tcertId))); };
  useEffect(() => { void reload(); }, []);
  const restore = async (id: string): Promise<void> => { const config = await safe(qrs().config.get()); if (!config.ok) return; await qrs().config.set({ ...config.value, archivedTcerts: (config.value.archivedTcerts ?? []).filter((x) => x !== id) }); void reload(); };
  return <Box><Button startIcon={<ArrowBackIcon />} onClick={() => onNavigate('settings')} sx={{ mb: 1 }}>Back to Settings</Button><Typography variant="h5" sx={{ mb: 2 }}>Archived TCerts</Typography><Card><CardContent>{certs.length === 0 ? <Alert severity="info">No archived TCerts.</Alert> : <List dense>{certs.map((cert) => <ListItem key={cert.tcertId} secondaryAction={<Button size="small" startIcon={<LockOpenIcon />} onClick={() => void restore(cert.tcertId)}>Restore</Button>}><ListItemText primary={cert.name} secondary={cert.tcertId} /></ListItem>)}</List>}</CardContent></Card></Box>;
}
