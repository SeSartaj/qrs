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
  Typography,
} from '@mui/material';
import { api, type ManagedTcert } from '../lib/api';
import { FieldValueInput } from '../components/FieldValueInput';

export function SignPage() {
  const [tcerts, setTcerts] = useState<ManagedTcert[]>([]);
  const [selectedId, setSelectedId] = useState<number | ''>('');
  const [values, setValues] = useState<Record<string, unknown>>({});
  const [result, setResult] = useState<string>('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .listTcerts()
      .then((list) => {
        const signable = list.filter((t) => t.has_schema);
        console.info('[QRS][Sign] loaded TCerts', signable.map((t) => ({
          id: t.id,
          name: t.name,
          tcert_id: t.tcert_id,
          schema: t.schema.map((f) => ({ name: f.name, type: f.type, valueType: typeof f.default })),
        })));
        setTcerts(signable);
      })
      .catch((e) => {
        console.error('[QRS][Sign] failed to load TCerts', e);
        setError(e.message);
      });
  }, []);

  const selected = tcerts.find((t) => t.id === selectedId);

  useEffect(() => {
    if (!selected) return;
    console.info('[QRS][Sign] selected TCert schema', {
      id: selected.id,
      tcert_id: selected.tcert_id,
      fields: selected.schema.map((field) => ({
        name: field.name,
        type: field.type,
        defaultPresent: field.default !== undefined,
        rules: field.input_rules,
      })),
    });
  }, [selected]);

  const submit = async () => {
    if (!selected) return;
    console.info('[QRS][Sign] submitting values', Object.fromEntries(
      Object.entries(values).map(([name, value]) => [name, { type: typeof value, isFinite: typeof value === 'number' ? Number.isFinite(value) : undefined }]),
    ));
    setBusy(true);
    setError('');
    setResult('');
    try {
      const rec = await api.signSdoc(selected.id, values);
      setResult(`Signed SDoc ${rec.sdoc_id}`);
    } catch (e) {
      console.error('[QRS][Sign] signing failed', e);
      setError(e instanceof Error ? e.message : 'Signing failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Sign a document
      </Typography>
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      {result && <Alert severity="success" sx={{ mb: 2 }}>{result}</Alert>}
      <Card>
        <CardContent>
          <FormControl fullWidth sx={{ mb: 2 }}>
            <InputLabel>TCert</InputLabel>
            <Select
              value={selectedId}
              onChange={(e) => {
                setSelectedId(e.target.value as number);
                setValues({});
              }}
              label="TCert"
            >
              {tcerts.map((t) => (
                <MenuItem key={t.id} value={t.id}>
                  {t.name} ({t.tcert_id})
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          {selected &&
            selected.schema.map((field) => (
              <Box key={field.name} sx={{ mb: 2 }}>
                <FieldValueInput
                  field={field}
                  value={values[field.name]}
                  onChange={(v) => setValues((prev) => ({ ...prev, [field.name]: v }))}
                />
              </Box>
            ))}
          {selected && (
            <Button variant="contained" onClick={submit} disabled={busy} sx={{ mt: 2 }}>
              {busy ? 'Signing…' : 'Sign document'}
            </Button>
          )}
        </CardContent>
      </Card>
    </Box>
  );
}
