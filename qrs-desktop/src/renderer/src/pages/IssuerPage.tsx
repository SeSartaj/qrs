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
  Grid,
  IconButton,
  InputLabel,
  MenuItem,
  Select,
  TextField,
  Typography,
  Tooltip,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import ArrowDownwardIcon from '@mui/icons-material/ArrowDownward';
import ArrowUpwardIcon from '@mui/icons-material/ArrowUpward';
import DeleteOutlineIcon from '@mui/icons-material/DeleteOutline';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import type { AlgorithmId, FieldSchema, FieldType } from 'qrs-core';
import { FIELD_TYPES } from 'qrs-core';
import { useTranslation } from 'react-i18next';
import type { KeySummary } from '@shared/types';
import { qrs, safe, shortId } from '../api';
import { FlexDateTimeInput } from '../components/FlexDateTimeInput';
import { ObjectActions } from '../components/ObjectActions';

type ShowNotice = (severity: 'success' | 'error' | 'info', text: string) => void;

const YEAR = 31_536_000; // seconds

/** Sentinel value meaning "generate a brand new key pair". */
export const NEW_KEY = '__new__';

interface DraftField {
  id: number;
  type: FieldType;
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

const emptyField = (id: number, type: FieldType = 'text'): DraftField => ({
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

/** Field types that may carry a value binding (verifier re-enters the value). */
const BINDING_TYPES = new Set<FieldType>(['secretInput', 'text', 'select', 'number', 'date']);

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
    if (f.maxRadius) field.verifyRules = { maxRadius: Number(f.maxRadius) };
  } else if (f.type === 'date' || f.type === 'datetime' || f.type === 'datetimeEpoch') {
    const lines = f.dateExpressions
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);
    if (lines.length > 0) field.verifyRules = { expressions: lines };
  } else if (f.type === 'attachment') {
    ir.contentType = f.contentType.trim() || 'image/png';
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
  if (Object.keys(ir).length > 0) field.inputRules = ir;
  return field;
}

export function IssuerPage({ showNotice, onCreated, onBack }: { showNotice: ShowNotice; onCreated: (tcertId: string) => void; onBack: () => void }) {
  const { t } = useTranslation();
  const [algorithm, setAlgorithm] = useState<AlgorithmId>('Ed25519');
  const [name, setName] = useState('');
  const [onlineEndpoint, setOnlineEndpoint] = useState('');
  const [validAfter, setValidAfter] = useState<number | undefined>(undefined);
  const [validBefore, setValidBefore] = useState<number | undefined>(undefined);
  const [sdocMaxAge, setSdocMaxAge] = useState('');
  const [fields, setFields] = useState<DraftField[]>([]);
  const [schemaMode, setSchemaMode] = useState<'create' | 'import'>('create');
  const [schemaImported, setSchemaImported] = useState(false);
  const [busy, setBusy] = useState(false);
  const [createdTcert, setCreatedTcert] = useState<{ tcertId: string; keyId: string; name: string; bytesB64: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Key selection: reuse an existing key pair or generate a fresh one.
  const [keys, setKeys] = useState<KeySummary[]>([]);
  const [keyChoice, setKeyChoice] = useState<string>(NEW_KEY);

  useEffect(() => {
    void (async () => {
      const res = await safe(qrs().keys.list());
      if (res.ok) setKeys(res.value);
    })();
  }, []);

  const updateField = (id: number, patch: Partial<DraftField>): void =>
    setFields((prev) => prev.map((f) => (f.id === id ? { ...f, ...patch } : f)));

  const addField = (): void => setFields((prev) => [...prev, emptyField(Math.max(0, ...prev.map((f) => f.id)) + 1)]);

  const removeField = (id: number): void => setFields((prev) => prev.filter((f) => f.id !== id));

  const moveField = (id: number, delta: -1 | 1): void =>
    setFields((prev) => {
      const idx = prev.findIndex((f) => f.id === id);
      const target = idx + delta;
      if (idx < 0 || target < 0 || target >= prev.length) return prev;
      const next = [...prev];
      const [field] = next.splice(idx, 1);
      next.splice(target, 0, field);
      return next;
    });

  const importSchema = async (): Promise<void> => {
    const result = await safe(qrs().certificates.importSchema());
    if (!result.ok) { setError(result.error); return; }
    setSchemaImported(true);
    setFields(result.value.map((field, index) => {
      const rules = field.inputRules ?? {};
      const options = Array.isArray(field.options) ? field.options.join(', ') : Array.isArray(rules.options) ? rules.options.map((o) => typeof o === 'string' ? o : `${(o as { label?: string }).label ?? ''}=${(o as { value?: string }).value ?? ''}`).join('\n') : '';
      return { ...emptyField(index + 1, field.type as FieldType), name: field.name, label: field.label, options, required: rules.required === true, minLength: String(rules.minLength ?? ''), maxLength: String(rules.maxLength ?? ''), min: String(rules.min ?? ''), max: String(rules.max ?? ''), maxRadius: String((field.verifyRules as { maxRadius?: unknown } | undefined)?.maxRadius ?? ''), binding: field.binding === 'stripped' ? 'stripped' : field.binding === 'inline' ? 'inline' : 'none', defaultValue: typeof field.default === 'string' ? field.default : field.default ? 'now' : '', contentType: String(rules.contentType ?? 'image/png'), dateExpressions: Array.isArray((field.verifyRules as { expressions?: unknown[] } | undefined)?.expressions) ? ((field.verifyRules as { expressions: unknown[] }).expressions).join('\n') : '' };
    }));
  };

  const setValidityYears = (years: number): void => {
    const now = Math.floor(Date.now() / 1000);
    setValidAfter(now);
    setValidBefore(now + years * YEAR);
  };

  const create = async (): Promise<void> => {
    setError(null);
    if (!name.trim()) {
      setError(t('issuer.errName'));
      return;
    }
    if (schemaMode === 'import' && !schemaImported) {
      setError('Choose a schema file before creating the TCert.');
      return;
    }
    if (fields.length > 0 && fields.some((f) => !f.name.trim() || !f.label.trim())) {
      setError(t('issuer.errFieldMeta'));
      return;
    }
    if (validAfter !== undefined && validBefore !== undefined && validAfter >= validBefore) {
      setError(t('issuer.validAfter') + ' < ' + t('issuer.validBefore'));
      return;
    }
    const sdocMaxAgeSeconds = sdocMaxAge.trim() !== '' ? Number(sdocMaxAge.trim()) : undefined;
    if (sdocMaxAgeSeconds !== undefined && (!Number.isFinite(sdocMaxAgeSeconds) || sdocMaxAgeSeconds <= 0)) {
      setError('SDoc validity duration must be a positive number of seconds');
      return;
    }
    setBusy(true);
    const res = await safe(
      qrs().certificates.create({
        algorithm,
        name: name.trim(),
        fields: fields.map(draftToSchema),
        onlineEndpoint: onlineEndpoint.trim() || undefined,
        validAfter,
        validBefore,
        sdocMaxAgeSeconds,
        keyId: keyChoice === NEW_KEY ? undefined : keyChoice,
      })
    );
    setBusy(false);
    if (!res.ok) {
      setError(res.error);
      return;
    }
    setCreatedTcert({ tcertId: res.value.tcertId, keyId: res.value.keyId, name: res.value.name, bytesB64: res.value.bytesB64 });
    showNotice('success', `TCert created: ${shortId(res.value.tcertId)}`);
    onCreated(res.value.tcertId);
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 3 }}>
        <Tooltip title="Back to Settings"><IconButton onClick={onBack}><ArrowBackIcon /></IconButton></Tooltip>
        <Typography variant="h5">{t('issuer.title')}</Typography>
      </Box>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}
      {createdTcert && (
        <Alert
          severity="success"
          sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}
          onClose={() => setCreatedTcert(null)}
        >
          <Box sx={{ flexGrow: 1 }}>
            TCert <b>{shortId(createdTcert.tcertId)}</b> {t('issuer.created')}
          </Box>
          <ObjectActions
            type="tcert"
            bytesB64={createdTcert.bytesB64}
            fileName={createdTcert.name || createdTcert.tcertId}
            qrTitle="TCert QR"
            showNotice={showNotice}
          />
        </Alert>
      )}

      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Grid container spacing={2}>
            <Grid size={{ xs: 12, sm: 4 }}>
              <FormControl fullWidth size="small">
                <InputLabel>{t('issuer.algorithm')}</InputLabel>
                <Select value={algorithm} label={t('issuer.algorithm')} onChange={(e) => setAlgorithm(e.target.value as AlgorithmId)}>
                  <MenuItem value="Ed25519">Ed25519 (64-byte signature)</MenuItem>
                  <MenuItem value="ECDSA-P256">ECDSA P-256 (64-byte signature)</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField label={t('issuer.name')} value={name} onChange={(e) => setName(e.target.value)} fullWidth slotProps={{ htmlInput: { dir: 'auto' } }} />
            </Grid>
            <Grid size={12}>
              <FormControl fullWidth size="small">
                <InputLabel>{t('issuer.keyPair')}</InputLabel>
                <Select
                  value={keyChoice}
                  label={t('issuer.keyPair')}
                  onChange={(e) => setKeyChoice(e.target.value)}
                >
                  <MenuItem value={NEW_KEY}>{t('issuer.newKeyPair')}</MenuItem>
                  {keys.map((k) => (
                    <MenuItem key={k.keyId} value={k.keyId}>
                      {shortId(k.keyId)} · {k.algorithm} · {k.tcertCount} TCert(s)
                    </MenuItem>
                  ))}
                </Select>
                <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
                  {t('issuer.keyPairHint')}
                </Typography>
              </FormControl>
            </Grid>
            <Grid size={12}>
              <TextField
                label="Online endpoint (distribution server URL)"
                placeholder="https://qrs.example.org"
                value={onlineEndpoint}
                onChange={(e) => setOnlineEndpoint(e.target.value)}
                fullWidth
                helperText="Signed into the TCert so verifiers can discover this server; the server itself is never trusted."
              />
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField
                label="SDoc validity duration (seconds)"
                placeholder="604800 = one week"
                type="number"
                value={sdocMaxAge}
                onChange={(e) => setSdocMaxAge(e.target.value)}
                fullWidth
                helperText="Every SDoc this certificate issues becomes invalid after this age (leave empty for no limit)."
              />
            </Grid>
          </Grid>

          <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>
            {t('issuer.validAfter')} / {t('issuer.validBefore')} (UTC)
          </Typography>
          <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 1 }}>
            {t('issuer.validityHint')}
          </Typography>
          <Grid container spacing={2}>
            <Grid size={{ xs: 12, sm: 6 }}>
              <FlexDateTimeInput kind="date" epoch label={t('issuer.validAfter')} value={validAfter} onChange={(v) => setValidAfter(v as number | undefined)} fullWidth />
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <FlexDateTimeInput kind="date" epoch label={t('issuer.validBefore')} value={validBefore} onChange={(v) => setValidBefore(v as number | undefined)} fullWidth />
            </Grid>
          </Grid>
          <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
            <Button size="small" variant="outlined" onClick={() => setValidityYears(5)}>
              {t('issuer.years5')}
            </Button>
            <Button size="small" variant="outlined" onClick={() => setValidityYears(10)}>
              {t('issuer.years10')}
            </Button>
            <Button size="small" variant="text" onClick={() => { setValidAfter(undefined); setValidBefore(undefined); }}>
              {t('common.cancel')}
            </Button>
          </Box>
        </CardContent>
      </Card>

      <Typography variant="h6" sx={{ mb: 1 }}>
        {t('issuer.documentSchema')}
      </Typography>
      <FormControl fullWidth size="small" sx={{ mb: 2 }}>
        <InputLabel>Schema source</InputLabel>
        <Select value={schemaMode} label="Schema source" onChange={(e) => { setSchemaMode(e.target.value as 'create' | 'import'); setSchemaImported(false); }}>
          <MenuItem value="create">Create a new schema</MenuItem>
          <MenuItem value="import">Import an existing schema</MenuItem>
        </Select>
      </FormControl>
      {schemaMode === 'import' && <Button variant="outlined" onClick={() => void importSchema()} sx={{ mb: 2 }}>Choose schema file</Button>}
      {fields.map((f, idx) => (
        <Card key={f.id} sx={{ mb: 1.5 }}>
          <CardContent>
            <Grid container spacing={1.5} alignItems="center">
              <Grid size={{ xs: 12, sm: 2 }}>
                <FormControl fullWidth size="small">
                  <InputLabel>{t('issuer.fieldType')}</InputLabel>
                  <Select
                    value={f.type}
                    label={t('issuer.fieldType')}
                    onChange={(e) => updateField(f.id, { type: e.target.value as FieldType })}
                  >
                    {FIELD_TYPES.map((ft) => (
                      <MenuItem key={ft} value={ft}>
                        {ft}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid size={{ xs: 12, sm: 3 }}>
                <TextField
                  label={t('issuer.fieldName')}
                  placeholder="pharmacy_name"
                  value={f.name}
                  onChange={(e) => updateField(f.id, { name: e.target.value })}
                  fullWidth
                  slotProps={{ htmlInput: { dir: 'auto' } }}
                />
              </Grid>
              <Grid size={{ xs: 12, sm: 4 }}>
                <TextField
                  label={t('issuer.fieldLabel')}
                  placeholder="Pharmacy Name"
                  value={f.label}
                  onChange={(e) => updateField(f.id, { label: e.target.value })}
                  fullWidth
                  slotProps={{ htmlInput: { dir: 'auto' } }}
                />
              </Grid>
              <Grid size={{ xs: 12, sm: 2 }}>
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={f.required}
                      onChange={(e) => updateField(f.id, { required: e.target.checked })}
                    />
                  }
                  label={t('issuer.required')}
                />
              </Grid>
              <Grid size={1}>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  <IconButton size="small" onClick={() => moveField(f.id, -1)} disabled={idx === 0} aria-label="move field up">
                    <ArrowUpwardIcon fontSize="small" />
                  </IconButton>
                  <IconButton size="small" onClick={() => moveField(f.id, 1)} disabled={idx === fields.length - 1} aria-label="move field down">
                    <ArrowDownwardIcon fontSize="small" />
                  </IconButton>
                  <IconButton onClick={() => removeField(f.id)} disabled={fields.length === 0} aria-label="remove field">
                    <DeleteOutlineIcon />
                  </IconButton>
                </Box>
              </Grid>

              {f.type === 'select' && (
                <Grid size={12}>
                  <TextField
                    label={t('issuer.options')}
                    placeholder="category_1, category_2"
                    value={f.options}
                    onChange={(e) => updateField(f.id, { options: e.target.value })}
                    fullWidth
                    size="small"
                  />
                </Grid>
              )}
              {f.type === 'selectv2' && (
                <Grid size={12}>
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
                  />
                </Grid>
              )}
              {(f.type === 'text' || f.type === 'textarea') && (
                <Grid size={{ xs: 12, sm: 6 }}>
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    <TextField
                      label={t('issuer.minLength')}
                      type="number"
                      value={f.minLength}
                      onChange={(e) => updateField(f.id, { minLength: e.target.value })}
                    />
                    <TextField
                      label={t('issuer.maxLength')}
                      type="number"
                      value={f.maxLength}
                      onChange={(e) => updateField(f.id, { maxLength: e.target.value })}
                    />
                  </Box>
                </Grid>
              )}
              {f.type === 'number' && (
                <Grid size={{ xs: 12, sm: 6 }}>
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    <TextField
                      label={t('issuer.min')}
                      type="number"
                      value={f.min}
                      onChange={(e) => updateField(f.id, { min: e.target.value })}
                    />
                    <TextField
                      label={t('issuer.max')}
                      type="number"
                      value={f.max}
                      onChange={(e) => updateField(f.id, { max: e.target.value })}
                    />
                  </Box>
                </Grid>
              )}
              {f.type === 'location' && (
                <Grid size={{ xs: 12, sm: 6 }}>
                  <TextField
                    label={t('issuer.maxRadius')}
                    type="number"
                    value={f.maxRadius}
                    onChange={(e) => updateField(f.id, { maxRadius: e.target.value })}
                  />
                </Grid>
              )}
              {(f.type === 'date' || f.type === 'datetime' || f.type === 'datetimeEpoch') && (
                <Grid size={12}>
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
                  />
                </Grid>
              )}
              {BINDING_TYPES.has(f.type) && (
                <Grid size={{ xs: 12, sm: 6 }}>
                  <FormControl fullWidth size="small">
                    <InputLabel>{t('issuer.binding')}</InputLabel>
                    <Select
                      value={f.binding}
                      label={t('issuer.binding')}
                      onChange={(e) => updateField(f.id, { binding: e.target.value as 'none' | 'stripped' | 'inline' })}
                    >
                      {f.type !== 'secretInput' && <MenuItem value="none">None</MenuItem>}
                      <MenuItem value="stripped">{t('issuer.stripped')}</MenuItem>
                      <MenuItem value="inline">{t('issuer.inline')}</MenuItem>
                    </Select>
                    <Typography variant="caption" color="text.secondary">
                      {f.type === 'secretInput'
                        ? 'A secret the verifier must re-enter; stripped keeps it out of the document.'
                        : 'The verifier must re-enter this value at verification time. inline (default) stores it; stripped signs-but-does-not-store.'}
                    </Typography>
                  </FormControl>
                </Grid>
              )}
              {f.type !== 'attachment' && f.type !== 'location' && (
                <Grid size={{ xs: 12, sm: 6 }}>
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
                  />
                </Grid>
              )}
              {f.type === 'attachment' && (
                <Grid size={{ xs: 12, sm: 6 }}>
                  <TextField
                    label={t('issuer.contentType')}
                    value={f.contentType}
                    onChange={(e) => updateField(f.id, { contentType: e.target.value })}
                  />
                </Grid>
              )}
              {idx + 1 === fields.length && (
                <Grid size={12}>
                  <Button size="small" startIcon={<AddIcon />} onClick={addField}>
                    {t('issuer.addField')}
                  </Button>
                </Grid>
              )}
            </Grid>
          </CardContent>
        </Card>
      ))}
      {fields.length === 0 && (
        <Card sx={{ mb: 1.5 }}>
          <CardContent>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
              No document fields — this will be a CA/meta certificate used for attestation, revocation and blocking. It cannot sign documents.
            </Typography>
            <Button size="small" startIcon={<AddIcon />} onClick={addField}>
              {t('issuer.addField')}
            </Button>
          </CardContent>
        </Card>
      )}

      <Button variant="contained" size="large" onClick={create} disabled={busy} sx={{ mt: 1 }}>
        {busy ? t('issuer.creating') : t('issuer.create')}
      </Button>
    </Box>
  );
}
