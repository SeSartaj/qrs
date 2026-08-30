import { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Divider,
  Typography,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import { api, type SdocRecord } from '../lib/api';
import { ObjectActions } from '../components/ObjectActions';
import { useNotice } from '../lib/notice';

interface Props {
  sdocId: string;
  onBack: () => void;
}

export function SdocDetailPage({ sdocId, onBack }: Props) {
  const { showNotice } = useNotice();
  const [sdoc, setSdoc] = useState<SdocRecord | null>(null);
  const [verdict, setVerdict] = useState<Record<string, string> | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    api
      .getSdoc(sdocId)
      .then(setSdoc)
      .catch((e) => setError(e.message));
  }, [sdocId]);

  const verify = async () => {
    if (!sdoc) return;
    setError('');
    try {
      setVerdict(await api.verifySdoc(sdoc.sdoc_b64));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Verification failed');
    }
  };

  if (error) return <Alert severity="error">{error}</Alert>;
  if (!sdoc) return null;

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
        <Button startIcon={<ArrowBackIcon />} onClick={onBack}>
          Back
        </Button>
      </Box>
      <Card>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <Box>
              <Typography variant="h5">SDoc</Typography>
              <Typography variant="body2" color="text.secondary">
                {sdoc.sdoc_id}
              </Typography>
              <Box sx={{ mt: 1 }}>
                <Chip label={`TCert ${sdoc.tcert_id}`} size="small" sx={{ mr: 1 }} />
                <Chip label={`Signed by ${sdoc.signed_by ?? '—'}`} size="small" />
              </Box>
            </Box>
            <ObjectActions
              type="sdoc"
              bytesB64={sdoc.sdoc_b64}
              qrTitle="SDoc"
              fileName={sdoc.sdoc_id}
              showNotice={showNotice}
            />
          </Box>
          <Divider sx={{ my: 2 }} />
          <Typography variant="body2" color="text.secondary">
            Issued at: {new Date(sdoc.issued_at * 1000).toLocaleString()}
          </Typography>
          <Button variant="contained" onClick={verify} sx={{ mt: 2 }}>
            Verify
          </Button>
          {verdict && (
            <Box sx={{ mt: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Verification result
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                {Object.entries(verdict).map(([k, v]) => (
                  <Chip
                    key={k}
                    label={`${k}: ${v}`}
                    size="small"
                    color={v === 'valid' ? 'success' : v === 'cannotVerify' ? 'warning' : 'error'}
                  />
                ))}
              </Box>
            </Box>
          )}
        </CardContent>
      </Card>
    </Box>
  );
}