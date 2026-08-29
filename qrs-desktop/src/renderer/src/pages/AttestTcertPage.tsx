import { useEffect, useState } from 'react';
import { Alert, Box, Button, Card, CardContent, FormControl, InputLabel, MenuItem, Select, TextField, Typography } from '@mui/material';
import { decodeBundle, decodeTransferPayload } from 'qrs-core';
import type { TcertSummary } from '@shared/types';
import { qrs, safe, shortId } from '../api';

export function AttestTcertPage({ ca, onBack, showNotice }: { ca: TcertSummary; onBack: () => void; showNotice: (s: 'success'|'error'|'info', m: string) => void }) {
  const [certs, setCerts] = useState<TcertSummary[]>([]); const [target, setTarget] = useState(''); const [claims, setClaims] = useState(''); const [importB64, setImportB64] = useState(''); const [error, setError] = useState<string | null>(null);
  useEffect(() => { void safe(qrs().certificates.list()).then((r) => { if (r.ok) setCerts(r.value); }); }, []);
  const importPayload = async (payload: string): Promise<void> => {
    const direct = decodeTransferPayload(payload);
    const bundled = decodeBundle(payload);
    const item = direct?.type === 'tcert' ? direct : bundled?.objects.find((x) => x.type === 'tcert');
    if (!item) { setError('The .qrs file does not contain a TCert.'); return; }
    const result = await safe(qrs().certificates.import(item.bytesB64));
    if (!result.ok) { setError(result.error); return; }
    setCerts((current) => current.some((x) => x.tcertId === result.value.tcertId) ? current : [...current, result.value]); setTarget(result.value.tcertId); setImportB64(''); setError(null);
  };
  const importFile = (file: File): void => { const reader = new FileReader(); reader.onload = () => { if (typeof reader.result === 'string') void importPayload(reader.result); }; reader.onerror = () => setError('Could not read the .qrs file.'); reader.readAsText(file); };
  const attest = async (): Promise<void> => { if (!target) return setError('Select or import a target TCert.'); let parsed; try { parsed = claims.trim() ? JSON.parse(claims) : undefined; } catch { return setError('Claims must be valid JSON.'); } const r = await safe(qrs().trust.attest({ caTcertId: ca.tcertId, targetTcertId: target, claims: parsed })); if (!r.ok) return setError(r.error); showNotice('success', 'TCert attested'); onBack(); };
  return <Box><Button onClick={onBack}>Back</Button><Typography variant="h5" sx={{ mb: 2 }}>Attest a TCert with {ca.name}</Typography>{error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}<Card><CardContent><Button component="label" variant="outlined" sx={{ mb: 1 }}>Choose .qrs file<input hidden type="file" accept=".qrs,text/plain" onChange={(e) => { const file = e.target.files?.[0]; if (file) importFile(file); e.target.value = ''; }} /></Button><TextField fullWidth multiline minRows={2} label="Or paste .qrs payload" value={importB64} onChange={(e) => setImportB64(e.target.value)} sx={{ mb: 1 }} /><Button onClick={() => void importPayload(importB64.trim())} disabled={!importB64.trim()} sx={{ mb: 2 }}>Import TCert</Button><FormControl fullWidth sx={{ mb: 1 }}><InputLabel>Available TCert</InputLabel><Select value={target} label="Available TCert" onChange={(e) => setTarget(e.target.value)}>{certs.filter((x) => x.tcertId !== ca.tcertId).map((x) => <MenuItem key={x.tcertId} value={x.tcertId}>{x.name} ({shortId(x.tcertId)})</MenuItem>)}</Select></FormControl><TextField fullWidth label="Claims JSON (optional)" value={claims} onChange={(e) => setClaims(e.target.value)} sx={{ mb: 1 }} /><Button variant="contained" onClick={() => void attest()}>Attest TCert</Button></CardContent></Card></Box>;
}
