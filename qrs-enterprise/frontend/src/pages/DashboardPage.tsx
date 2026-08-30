import { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Card,
  CardContent,
  Chip,
  Grid,
  Typography,
} from '@mui/material';
import { api, type ManagedTcert } from '../lib/api';

interface Props {
  onSelectTcert: (id: number) => void;
}

export function DashboardPage({ onSelectTcert }: Props) {
  const [tcerts, setTcerts] = useState<ManagedTcert[]>([]);
  const [error, setError] = useState('');

  useEffect(() => {
    api
      .listTcerts()
      .then(setTcerts)
      .catch((e) => setError(e.message));
  }, []);

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Dashboard
      </Typography>
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      <Typography variant="body1" gutterBottom>
        TCerts you can sign with:
      </Typography>
      <Grid container spacing={2}>
        {tcerts.map((t) => (
          <Grid size={{ xs: 12, md: 6 }} key={t.id}>
            <Card sx={{ cursor: 'pointer' }} onClick={() => onSelectTcert(t.id)}>
              <CardContent>
                <Typography variant="h6">{t.name}</Typography>
                <Typography variant="body2" color="text.secondary">
                  {t.tcert_id}
                </Typography>
                <Box sx={{ mt: 1 }}>
                  <Chip label={t.algorithm} size="small" sx={{ mr: 1 }} />
                  {t.is_ca && <Chip label="CA" size="small" color="primary" sx={{ mr: 1 }} />}
                  {t.has_schema && <Chip label="Signing" size="small" color="success" />}
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
        {tcerts.length === 0 && (
          <Grid size={{ xs: 12 }}>
            <Typography color="text.secondary">No TCerts available.</Typography>
          </Grid>
        )}
      </Grid>
    </Box>
  );
}