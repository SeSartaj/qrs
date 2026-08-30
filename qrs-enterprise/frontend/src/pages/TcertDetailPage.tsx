import { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  Typography,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import { api, type Grant, type ManagedTcert, type SdocRecord } from '../lib/api';
import { ObjectActions } from '../components/ObjectActions';
import { SdocTable } from '../components/SdocTable';
import { FieldValueInput } from '../components/FieldValueInput';
import { useNotice } from '../lib/notice';

interface Props {
  tcertId: number;
  onBack: () => void;
  onOpenSdoc: (sdocId: string) => void;
}

export function TcertDetailPage({ tcertId, onBack, onOpenSdoc }: Props) {
  const { showNotice } = useNotice();
  const [tcert, setTcert] = useState<ManagedTcert | null>(null);
  const [grants, setGrants] = useState<Grant[]>([]);
  const [sdocs, setSdocs] = useState<SdocRecord[]>([]);
  const [error, setError] = useState('');
  const [signOpen, setSignOpen] = useState(false);
  const [values, setValues] = useState<Record<string, unknown>>({});
  const [signBusy, setSignBusy] = useState(false);
  const [signError, setSignError] = useState('');

  useEffect(() => {
    api
      .getTcert(tcertId)
      .then(setTcert)
      .catch((e) => setError(e.message));
    api
      .listGrants(tcertId)
      .then(setGrants)
      .catch(() => {});
    api
      .listSdocs()
      .then((list) => setSdocs(list.filter((s) => s.tcert_id === tcert?.tcert_id)))
      .catch(() => {});
  }, [tcertId, tcert?.tcert_id]);

  const openSign = () => {
    setValues({});
    setSignError('');
    setSignOpen(true);
  };

  const submitSign = async () => {
    if (!tcert) return;
    setSignBusy(true);
    setSignError('');
    try {
      const rec = await api.signSdoc(tcert.id, values);
      setSignOpen(false);
      showNotice('success', `Signed SDoc ${rec.sdoc_id}`);
      setSdocs((prev) => [rec, ...prev]);
    } catch (e) {
      setSignError(e instanceof Error ? e.message : 'Signing failed');
    } finally {
      setSignBusy(false);
    }
  };

  if (error) return <Alert severity="error">{error}</Alert>;
  if (!tcert) return null;

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
        <Button startIcon={<ArrowBackIcon />} onClick={onBack}>
          Back
        </Button>
        {tcert.has_schema && (
          <Button variant="contained" onClick={openSign} sx={{ ml: 'auto' }}>
            Sign document
          </Button>
        )}
      </Box>
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <Box>
              <Typography variant="h5">{tcert.name}</Typography>
              <Typography variant="body2" color="text.secondary">
                {tcert.tcert_id}
              </Typography>
              <Box sx={{ mt: 1 }}>
                <Chip label={tcert.algorithm} size="small" sx={{ mr: 1 }} />
                {tcert.is_ca && <Chip label="CA" size="small" color="primary" sx={{ mr: 1 }} />}
                {tcert.has_schema && <Chip label="Signing" size="small" color="success" />}
              </Box>
            </Box>
            <ObjectActions
              type="tcert"
              bytesB64={tcert.tcert_id}
              qrTitle={`${tcert.name} — TCert`}
              fileName={tcert.name}
              showNotice={showNotice}
            />
          </Box>
          <Divider sx={{ my: 2 }} />
          <Typography variant="subtitle2" gutterBottom>
            Document schema
          </Typography>
          {tcert.schema.length === 0 && (
            <Typography variant="body2" color="text.secondary">
              No document schema (CA / meta certificate).
            </Typography>
          )}
          {tcert.schema.map((f) => (
            <Typography key={f.name} variant="body2">
              • {f.label} <em>({f.type})</em>
            </Typography>
          ))}
        </CardContent>
      </Card>

      <Typography variant="h6" gutterBottom>
        Grants ({grants.length})
      </Typography>
      {grants.map((g) => (
        <Typography key={g.id} variant="body2">
          {g.username}
        </Typography>
      ))}

      <Typography variant="h6" gutterBottom sx={{ mt: 3 }}>
        Documents issued by this certificate ({sdocs.length})
      </Typography>
      <SdocTable docs={sdocs} onOpen={onOpenSdoc} />

      <Dialog open={signOpen} onClose={() => setSignOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Sign a document with {tcert.name}</DialogTitle>
        <DialogContent>
          {signError && <Alert severity="error" sx={{ mb: 2 }}>{signError}</Alert>}
          {tcert.schema.map((field) => (
            <Box key={field.name} sx={{ mb: 2 }}>
              <FieldValueInput
                field={field}
                value={values[field.name]}
                onChange={(v) => setValues((prev) => ({ ...prev, [field.name]: v }))}
              />
            </Box>
          ))}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSignOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={submitSign} disabled={signBusy}>
            {signBusy ? 'Signing…' : 'Sign'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}