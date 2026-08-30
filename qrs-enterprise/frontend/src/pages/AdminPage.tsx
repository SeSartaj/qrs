import { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Checkbox,
  FormControl,
  FormControlLabel,
  InputLabel,
  MenuItem,
  Select,
  Tab,
  Tabs,
  TextField,
  Typography,
} from '@mui/material';
import { api, type ApiKeyInfo, type AuditLogEntry, type FieldSchema, type Grant, type ManagedTcert } from '../lib/api';

interface DraftField {
  id: number;
  type: string;
  name: string;
  label: string;
  options: string;
  required: boolean;
  minLength: string;
  maxLength: string;
  min: string;
  max: string;
  maxRadius: string;
  binding: 'none' | 'stripped' | 'inline';
  defaultValue: string;
  contentType: string;
  dateExpressions: string;
}

const FIELD_TYPES = ['text', 'textarea', 'select', 'selectv2', 'number', 'date', 'datetime', 'datetimeEpoch', 'secretInput', 'location'];

/** Field types that may carry a value binding (verifier re-enters the value). */
const BINDING_TYPES = new Set(['secretInput', 'text', 'select', 'number', 'date']);

const emptyField = (id: number, type: string = 'text'): DraftField => ({
  id,
  type,
  name: '',
  label: '',
  options: '',
  required: false,
  minLength: '',
  maxLength: '',
  min: '',
  max: '',
  maxRadius: '',
  binding: 'none',
  defaultValue: '',
  contentType: 'image/png',
  dateExpressions: '',
});

function draftToSchema(f: DraftField): FieldSchema {
  const field: FieldSchema = { type: f.type, name: f.name.trim(), label: f.label.trim() };
  const ir: Record<string, unknown> = {};
  if (f.required) ir.required = true;
  if (f.type === 'select') {
    field.options = f.options
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
  } else if (f.type === 'selectv2') {
    // Options may carry an optional color: "label=value=#color" or "label=value" or "label".
    const opts = f.options
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean)
      .map((line) => {
        const parts = line.split('=').map((p) => p.trim());
        if (parts.length >= 3) return { label: parts[0], value: parts[1], color: parts[2] };
        if (parts.length === 2) return { label: parts[0], value: parts[1] };
        return { label: parts[0], value: parts[0] };
      });
    ir.options = opts;
  } else if (f.type === 'text' || f.type === 'textarea') {
    if (f.minLength) ir.minLength = Number(f.minLength);
    if (f.maxLength) ir.maxLength = Number(f.maxLength);
  } else if (f.type === 'number') {
    if (f.min) ir.min = Number(f.min);
    if (f.max) ir.max = Number(f.max);
  } else if (f.type === 'location') {
    if (f.maxRadius) field.verify_rules = { maxRadius: Number(f.maxRadius) };
  } else if (f.type === 'date' || f.type === 'datetime' || f.type === 'datetimeEpoch') {
    const lines = f.dateExpressions
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);
    if (lines.length > 0) field.verify_rules = { expressions: lines };
  }
  // Value binding: secretInput is always bound (default stripped); the other
  // binding-capable types are bound only when explicitly chosen (default inline).
  if (f.type === 'secretInput') {
    field.binding = f.binding === 'none' ? 'stripped' : f.binding;
  } else if (BINDING_TYPES.has(f.type) && f.binding !== 'none') {
    field.binding = f.binding;
  }
  // Declared default: auto-filled at signing (hidden from the form). For
  // date/datetime, the value 'now' becomes the special {kind:'now'} default.
  if (f.defaultValue.trim() !== '') {
    if ((f.type === 'date' || f.type === 'datetime') && f.defaultValue.trim().toLowerCase() === 'now') {
      field.default = { kind: 'now' };
    } else {
      field.default = f.defaultValue.trim();
    }
  }
  if (Object.keys(ir).length > 0) field.input_rules = ir;
  return field;
}

export function AdminPage() {
  const [tab, setTab] = useState(0);

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Admin
      </Typography>
      <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2 }}>
        <Tab label="Create TCert" />
        <Tab label="Grants" />
        <Tab label="API keys" />
        <Tab label="Audit log" />
      </Tabs>
      {tab === 0 && <CreateTcertTab />}
      {tab === 1 && <GrantsTab />}
      {tab === 2 && <ApiKeysTab />}
      {tab === 3 && <LogsTab />}
    </Box>
  );
}

function CreateTcertTab() {
  const [name, setName] = useState('');
  const [algorithm, setAlgorithm] = useState('Ed25519');
  const [isCa, setIsCa] = useState(false);
  const [onlineEndpoint, setOnlineEndpoint] = useState('');
  const [fields, setFields] = useState<DraftField[]>([emptyField(1)]);
  const [result, setResult] = useState('');
  const [error, setError] = useState('');

  const updateField = (id: number, patch: Partial<DraftField>) =>
    setFields((prev) => prev.map((f) => (f.id === id ? { ...f, ...patch } : f)));
  const addField = () =>
    setFields((prev) => [...prev, emptyField(Math.max(0, ...prev.map((f) => f.id)) + 1)]);
  const removeField = (id: number) => setFields((prev) => prev.filter((f) => f.id !== id));

  const submit = async () => {
    setError('');
    setResult('');
    const schema: FieldSchema[] = fields
      .filter((f) => f.name && f.label)
      .map(draftToSchema);
    try {
      const tcert = await api.createTcert({
        algorithm,
        name,
        fields: schema,
        is_ca: isCa,
        online_endpoint: onlineEndpoint || undefined,
      });
      setResult(`Created TCert ${tcert.tcert_id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Creation failed');
    }
  };

  return (
    <Card>
      <CardContent>
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        {result && <Alert severity="success" sx={{ mb: 2 }}>{result}</Alert>}
        <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} fullWidth sx={{ mb: 2 }} />
        <FormControl fullWidth sx={{ mb: 2 }}>
          <InputLabel>Algorithm</InputLabel>
          <Select value={algorithm} onChange={(e) => setAlgorithm(e.target.value)} label="Algorithm">
            <MenuItem value="Ed25519">Ed25519</MenuItem>
            <MenuItem value="ECDSA-P256">ECDSA-P256</MenuItem>
          </Select>
        </FormControl>
        <TextField
          label="Online endpoint (qrs-server)"
          value={onlineEndpoint}
          onChange={(e) => setOnlineEndpoint(e.target.value)}
          fullWidth
          sx={{ mb: 2 }}
        />
        <FormControlLabel
          control={<Checkbox checked={isCa} onChange={(e) => setIsCa(e.target.checked)} />}
          label="This is a CA TCert"
        />
        <Typography variant="subtitle1" sx={{ mt: 2, mb: 1 }}>
          Document fields
        </Typography>
        {fields.map((f) => (
          <Card key={f.id} sx={{ mb: 1.5 }}>
            <CardContent>
              <Box sx={{ display: 'flex', gap: 1, mb: 1, alignItems: 'center' }}>
                <FormControl size="small" sx={{ minWidth: 140 }}>
                  <Select value={f.type} onChange={(e) => updateField(f.id, { type: e.target.value })}>
                    {FIELD_TYPES.map((t) => (
                      <MenuItem key={t} value={t}>
                        {t}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
                <TextField size="small" placeholder="name" value={f.name} onChange={(e) => updateField(f.id, { name: e.target.value })} />
                <TextField size="small" placeholder="label" value={f.label} onChange={(e) => updateField(f.id, { label: e.target.value })} />
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={f.required}
                      onChange={(e) => updateField(f.id, { required: e.target.checked })}
                    />
                  }
                  label="Required"
                />
                <Button size="small" color="error" onClick={() => removeField(f.id)}>
                  Remove
                </Button>
              </Box>

              {f.type === 'select' && (
                <TextField
                  label="Options"
                  placeholder="category_1, category_2"
                  value={f.options}
                  onChange={(e) => updateField(f.id, { options: e.target.value })}
                  fullWidth
                  size="small"
                  sx={{ mb: 1 }}
                />
              )}
              {f.type === 'selectv2' && (
                <TextField
                  label="Options (one per line: label=value=#color)"
                  placeholder={'Active=active=#34c98f\nExpired=expired=#ef6a6a'}
                  value={f.options}
                  onChange={(e) => updateField(f.id, { options: e.target.value })}
                  fullWidth
                  size="small"
                  multiline
                  minRows={2}
                  helperText="Only the selected option's index is stored in the SDoc; the label/value/color live in the TCert schema."
                  sx={{ mb: 1 }}
                />
              )}
              {(f.type === 'text' || f.type === 'textarea') && (
                <Box sx={{ display: 'flex', gap: 1, mb: 1 }}>
                  <TextField
                    label="Min length"
                    type="number"
                    value={f.minLength}
                    onChange={(e) => updateField(f.id, { minLength: e.target.value })}
                  />
                  <TextField
                    label="Max length"
                    type="number"
                    value={f.maxLength}
                    onChange={(e) => updateField(f.id, { maxLength: e.target.value })}
                  />
                </Box>
              )}
              {f.type === 'number' && (
                <Box sx={{ display: 'flex', gap: 1, mb: 1 }}>
                  <TextField
                    label="Min"
                    type="number"
                    value={f.min}
                    onChange={(e) => updateField(f.id, { min: e.target.value })}
                  />
                  <TextField
                    label="Max"
                    type="number"
                    value={f.max}
                    onChange={(e) => updateField(f.id, { max: e.target.value })}
                  />
                </Box>
              )}
              {f.type === 'location' && (
                <TextField
                  label="Max radius"
                  type="number"
                  value={f.maxRadius}
                  onChange={(e) => updateField(f.id, { maxRadius: e.target.value })}
                  sx={{ mb: 1 }}
                />
              )}
              {(f.type === 'date' || f.type === 'datetime' || f.type === 'datetimeEpoch') && (
                <TextField
                  label="Verification rules (one per line)"
                  multiline
                  minRows={2}
                  fullWidth
                  size="small"
                  value={f.dateExpressions}
                  onChange={(e) => updateField(f.id, { dateExpressions: e.target.value })}
                  placeholder=">today()\nday() == 'friday'\n16:00 < x < 23:00"
                  helperText="e.g. &gt;today(), day() == 'friday', daytime == 'night', 16:00 &lt; x &lt; 23:00"
                  sx={{ mb: 1 }}
                />
              )}
              {BINDING_TYPES.has(f.type) && (
                <FormControl fullWidth size="small" sx={{ mb: 1 }}>
                  <InputLabel>Binding</InputLabel>
                  <Select
                    value={f.binding}
                    label="Binding"
                    onChange={(e) => updateField(f.id, { binding: e.target.value as 'none' | 'stripped' | 'inline' })}
                  >
                    {f.type !== 'secretInput' && <MenuItem value="none">None</MenuItem>}
                    <MenuItem value="stripped">Stripped</MenuItem>
                    <MenuItem value="inline">Inline</MenuItem>
                  </Select>
                  <Typography variant="caption" color="text.secondary">
                    {f.type === 'secretInput'
                      ? 'A secret the verifier must re-enter; stripped keeps it out of the document.'
                      : 'The verifier must re-enter this value at verification time. inline (default) stores it; stripped signs-but-does-not-store.'}
                  </Typography>
                </FormControl>
              )}
              {f.type !== 'location' && (
                <TextField
                  label="Default value (hidden from the form)"
                  placeholder={f.type === 'date' || f.type === 'datetime' ? "'now' for the current time" : 'auto-filled value'}
                  value={f.defaultValue}
                  onChange={(e) => updateField(f.id, { defaultValue: e.target.value })}
                  fullWidth
                  size="small"
                  helperText={
                    f.type === 'date' || f.type === 'datetime'
                      ? "Enter 'now' to fill the current time at signing."
                      : 'Auto-filled at signing; the field is hidden from the form.'
                  }
                  sx={{ mb: 1 }}
                />
              )}
            </CardContent>
          </Card>
        ))}
        <Button onClick={addField} sx={{ mt: 1 }}>
          + Add field
        </Button>
        <Box sx={{ mt: 2 }}>
          <Button variant="contained" onClick={submit} disabled={!name}>
            Create TCert
          </Button>
        </Box>
      </CardContent>
    </Card>
  );
}

function GrantsTab() {
  const [tcerts, setTcerts] = useState<ManagedTcert[]>([]);
  const [tcertId, setTcertId] = useState<number | ''>('');
  const [grants, setGrants] = useState<Grant[]>([]);
  const [userId, setUserId] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    api.listTcerts().then(setTcerts).catch((e) => setError(e.message));
  }, []);

  const loadGrants = async (id: number) => {
    setGrants(await api.listGrants(id));
  };

  const addGrant = async () => {
    if (tcertId === '' || !userId) return;
    await api.addGrant(tcertId as number, Number(userId));
    await loadGrants(tcertId as number);
    setUserId('');
  };

  const removeGrant = async (grantId: number) => {
    if (tcertId === '') return;
    await api.removeGrant(tcertId as number, grantId);
    await loadGrants(tcertId as number);
  };

  return (
    <Card>
      <CardContent>
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        <FormControl fullWidth sx={{ mb: 2 }}>
          <InputLabel>TCert</InputLabel>
          <Select
            value={tcertId}
            onChange={(e) => {
              setTcertId(e.target.value as number);
              loadGrants(e.target.value as number);
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
        <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
          <TextField label="User ID" value={userId} onChange={(e) => setUserId(e.target.value)} />
          <Button variant="contained" onClick={addGrant} disabled={tcertId === '' || !userId}>
            Grant
          </Button>
        </Box>
        {grants.map((g) => (
          <Box key={g.id} sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
            <Typography>{g.username}</Typography>
            <Button size="small" color="error" onClick={() => removeGrant(g.id)}>
              Revoke
            </Button>
          </Box>
        ))}
      </CardContent>
    </Card>
  );
}

function ApiKeysTab() {
  const [keys, setKeys] = useState<ApiKeyInfo[]>([]);
  const [name, setName] = useState('');
  const [perms, setPerms] = useState<string[]>([]);
  const [newKey, setNewKey] = useState('');
  const [error, setError] = useState('');

  const PERM_OPTIONS = [
    'enterprise.can_sign',
    'enterprise.can_block_sdoc',
    'enterprise.can_unblock_sdoc',
  ];

  useEffect(() => {
    api.listApiKeys().then(setKeys).catch((e) => setError(e.message));
  }, []);

  const create = async () => {
    setError('');
    setNewKey('');
    try {
      const res = await api.createApiKey(name, perms);
      setNewKey(res.key);
      setKeys(await api.listApiKeys());
      setName('');
      setPerms([]);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Creation failed');
    }
  };

  const remove = async (id: number) => {
    await api.deleteApiKey(id);
    setKeys(await api.listApiKeys());
  };

  return (
    <Card>
      <CardContent>
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        {newKey && (
          <Alert severity="info" sx={{ mb: 2 }}>
            Save this key now — it will not be shown again: <strong>{newKey}</strong>
          </Alert>
        )}
        <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} fullWidth sx={{ mb: 2 }} />
        <Typography variant="subtitle2">Permissions</Typography>
        {PERM_OPTIONS.map((p) => (
          <FormControlLabel
            key={p}
            control={
              <Checkbox
                checked={perms.includes(p)}
                onChange={(e) =>
                  setPerms((prev) => (e.target.checked ? [...prev, p] : prev.filter((x) => x !== p)))
                }
              />
            }
            label={p}
          />
        ))}
        <Box sx={{ mt: 1 }}>
          <Button variant="contained" onClick={create} disabled={!name}>
            Create API key
          </Button>
        </Box>
        <Box sx={{ mt: 3 }}>
          {keys.map((k) => (
            <Box key={k.id} sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
              <Box>
                <Typography>
                  {k.name} ({k.key_prefix}…)
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {k.permissions.length ? k.permissions.join(', ') : 'no permissions'}
                </Typography>
              </Box>
              <Button size="small" color="error" onClick={() => remove(k.id)}>
                Delete
              </Button>
            </Box>
          ))}
        </Box>
      </CardContent>
    </Card>
  );
}

function LogsTab() {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [error, setError] = useState('');

  useEffect(() => {
    api.listLogs().then(setLogs).catch((e) => setError(e.message));
  }, []);

  return (
    <Card>
      <CardContent>
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        {logs.map((l) => (
          <Box key={l.id} sx={{ mb: 1 }}>
            <Typography variant="body2">
              <strong>{l.username ?? 'system'}</strong> · {l.action} · {l.target} · {l.ip_address ?? '—'} ·{' '}
              {new Date(l.created_at).toLocaleString()}
            </Typography>
          </Box>
        ))}
        {logs.length === 0 && <Typography color="text.secondary">No audit entries.</Typography>}
      </CardContent>
    </Card>
  );
}