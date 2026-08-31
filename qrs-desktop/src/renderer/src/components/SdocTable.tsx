import { useEffect, useMemo, useState } from 'react';
import {
  Box,
  Button,
  Card,
  Chip,
  Checkbox,
  CircularProgress,
  FormControlLabel,
  Menu,
  MenuItem,
  Select,
  Pagination,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import ViewColumnIcon from '@mui/icons-material/ViewColumn';
import type { DocumentSummary, DocumentValue } from '@shared/types';
import { qrs, safe, shortId, formatDate } from '../api';
import { OverflowMenu } from './OverflowMenu';

type TFunc = (key: string) => string;

const PAGE_SIZE_OPTIONS = [5,20, 50, 100];

/** Render a single decoded field value for table display. */
function renderValue(v: DocumentValue): string {
  const val = v.value;
  if (val === undefined || val === null || val === '') return '—';
  if (v.type === 'datetimeEpoch' && typeof val === 'number') return formatDate(val);
  if (typeof val === 'string' && v.type === 'attachment') {
    return `${v.contentType ?? 'file'} · ${val.slice(0, 12)}…`;
  }
  if (typeof val === 'object') {
    // location: { lat, lon }
    if ('lat' in val && 'lon' in val) {
      const loc = val as { lat: number; lon: number };
      return `${loc.lat.toFixed(5)}, ${loc.lon.toFixed(5)}`;
    }
    // attachment reference: compact hash string
    return JSON.stringify(val);
  }
  return String(val);
}

/**
 * Render a selectv2 value as a colored circle + label when the option declares a
 * color. The stored value is the option index; the color/label come from the
 * TCert schema (inputRules.options).
 */
function renderSelectV2(v: DocumentValue): { label: string; color?: string } {
  const idx = typeof v.value === 'number' ? v.value : -1;
  const raw = v.options;
  const options = Array.isArray(raw)
    ? raw.map((o) => (typeof o === 'string' ? { label: o, value: o } : (o as { label: string; value: string; color?: string })))
    : [];
  const opt = idx >= 0 && idx < options.length ? options[idx] : undefined;
  return { label: opt?.label ?? String(v.value ?? '—'), color: opt?.color };
}

/** A searchable, paginated SDoc table that shows the stored field values as columns. */
export function SdocTable({
  docs,
  onVerify,
  copy,
  t,
  onOpen,
  onBlock,
  pendingBlock,
}: {
  docs: DocumentSummary[];
  onVerify: (bytesB64: string) => void;
  copy: (text: string) => Promise<void>;
  t: TFunc;
  /** Open the details page for an SDoc. */
  onOpen: (sdocId: string) => void;
  onBlock?: (sdocId: string, unblock: boolean) => void;
  pendingBlock?: { sdocId: string; action: 'block' | 'unblock' } | null;
}) {
  const [query, setQuery] = useState('');
  const [columnMenu, setColumnMenu] = useState<null | HTMLElement>(null);
  const [hiddenColumns, setHiddenColumns] = useState<string[] | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(PAGE_SIZE_OPTIONS[0]);

  // Load the user's column preference from the global config store.
  useEffect(() => {
    void (async () => {
      const res = await safe(qrs().config.get());
      if (res.ok && Array.isArray(res.value.sdocColumns)) {
        setHiddenColumns(res.value.sdocColumns);
      }
    })();
  }, []);

  // The union of all field names across the docs (in first-seen order) becomes
  // the value columns. This adapts to whatever schema the TCert uses.
  const allColumns = useMemo(() => {
    const seen: string[] = [];
    for (const d of docs) {
      for (const v of d.values ?? []) {
        if (!seen.includes(v.name)) seen.push(v.name);
      }
    }
    return seen;
  }, [docs]);

  // By default show only the first two field columns. Once the user changes the
  // selection, the exact hidden-column list is persisted in global config.
  const effectiveHiddenColumns = hiddenColumns ?? allColumns.slice(2);
  const columns = useMemo(() => allColumns.filter((c) => !effectiveHiddenColumns.includes(c)), [allColumns, effectiveHiddenColumns]);

  const toggleColumn = (name: string): void => {
    setHiddenColumns((prev) => {
      const current = prev ?? allColumns.slice(2);
      const next = current.includes(name) ? current.filter((c) => c !== name) : [...current, name];
      void safe(qrs().config.get()).then((result) => {
        if (result.ok) void qrs().config.set({ ...result.value, sdocColumns: next });
      });
      return next;
    });
  };

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const chronological = [...docs].sort((a, b) => b.issuedAt - a.issuedAt);
    if (!q) return chronological;
    return chronological.filter((d) => {
      if (shortId(d.sdocId).toLowerCase().includes(q)) return true;
      if (formatDate(d.issuedAt).toLowerCase().includes(q)) return true;
      for (const v of d.values ?? []) {
        if (renderValue(v).toLowerCase().includes(q)) return true;
        if (v.label.toLowerCase().includes(q)) return true;
      }
      return false;
    });
  }, [docs, query]);

  // Reset to page 1 when the query or docs change.
  useEffect(() => {
    setPage(1);
  }, [query, docs]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const safePage = Math.min(page, pageCount);
  const pageDocs = filtered.slice((safePage - 1) * pageSize, safePage * pageSize);

  const valueFor = (d: DocumentSummary, name: string): DocumentValue | undefined =>
    d.values?.find((v) => v.name === name);

  // The human label for a column (from the first doc that has it).
  const labelFor = (name: string): string => {
    for (const d of docs) {
      const v = d.values?.find((x) => x.name === name);
      if (v?.label) return v.label;
    }
    return name;
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', gap: 1, mb: 1 }}>
        <TextField
          size="small"
          fullWidth
          placeholder="Search by SDoc id, date, or any field value…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          slotProps={{
            input: { startAdornment: <SearchIcon sx={{ mr: 1, color: 'text.secondary' }} /> },
          }}
        />
        <Button
          size="small"
          variant="outlined"
          startIcon={<ViewColumnIcon />}
          onClick={(e) => setColumnMenu(e.currentTarget)}
        >
          Columns
        </Button>
        <Select size="small" value={pageSize} onChange={(e) => { setPageSize(Number(e.target.value)); setPage(1); }}>
          {PAGE_SIZE_OPTIONS.map((size) => <MenuItem key={size} value={size}>{size} / page</MenuItem>)}
        </Select>
        <Menu anchorEl={columnMenu} open={Boolean(columnMenu)} onClose={() => setColumnMenu(null)}>
          {allColumns.map((c) => (
            <MenuItem key={c} dense>
              <FormControlLabel
                control={
                  <Checkbox
                    size="small"
                    checked={!effectiveHiddenColumns.includes(c)}
                    onChange={() => toggleColumn(c)}
                  />
                }
                label={labelFor(c)}
              />
            </MenuItem>
          ))}
        </Menu>
      </Box>
      <TableContainer component={Card}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>SDoc</TableCell>
              <TableCell>{t('documents.issued')}</TableCell>
              <TableCell>Status</TableCell>
              {columns.map((c) => (
                <TableCell key={c}>{labelFor(c)}</TableCell>
              ))}
              <TableCell align="right">{t('trust.actionsCol')}</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {pageDocs.map((d) => (
              <TableRow key={d.sdocId} hover sx={{ cursor: 'pointer' }} onClick={() => onOpen(d.sdocId)}>
                <TableCell sx={{ fontFamily: 'monospace', fontSize: 12, color: 'primary.main' }}>
                  {shortId(d.sdocId)}
                </TableCell>
                <TableCell sx={{ whiteSpace: 'nowrap' }}>{formatDate(d.issuedAt)}</TableCell>
                <TableCell>
                  {pendingBlock?.sdocId === d.sdocId ? (
                    <Chip
                      size="small"
                      icon={<CircularProgress size={14} color="inherit" />}
                      label={pendingBlock.action === 'block' ? 'Blocking…' : 'Unblocking…'}
                      color="warning"
                    />
                  ) : (
                    <Chip size="small" label={d.blocked ? 'Blocked' : 'Active'} color={d.blocked ? 'error' : 'success'} variant={d.blocked ? 'filled' : 'outlined'} />
                  )}
                </TableCell>
                {columns.map((c) => {
                  const v = valueFor(d, c);
                  if (!v) {
                    return (
                      <TableCell key={c} sx={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        —
                      </TableCell>
                    );
                  }
                  // selectv2: show a colored circle + label when the option has a color.
                  if (v.type === 'selectv2') {
                    const { label, color } = renderSelectV2(v);
                    return (
                      <TableCell key={c} sx={{ maxWidth: 220, whiteSpace: 'nowrap' }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          {color && (
                            <Box
                              sx={{
                                width: 12,
                                height: 12,
                                borderRadius: '50%',
                                backgroundColor: color,
                                flexShrink: 0,
                              }}
                            />
                          )}
                          <Typography variant="body2" sx={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {label}
                          </Typography>
                        </Box>
                      </TableCell>
                    );
                  }
                  return (
                    <TableCell key={c} sx={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {renderValue(v)}
                    </TableCell>
                  );
                })}
                <TableCell align="right" sx={{ whiteSpace: 'nowrap' }}>
                  <OverflowMenu disabled={pendingBlock?.sdocId === d.sdocId} actions={[{ label: 'Open details', onClick: () => onOpen(d.sdocId) }, { label: t('common.verify'), onClick: () => onVerify(d.bytesB64) }, { label: t('common.copy'), onClick: () => void copy(d.bytesB64) }, ...(onBlock ? [{ label: d.blocked ? 'Unblock SDoc' : 'Block SDoc', color: d.blocked ? ('inherit' as const) : ('error' as const), onClick: () => onBlock(d.sdocId, Boolean(d.blocked)) }] : [])]} />
                </TableCell>
              </TableRow>
            ))}
            {pageDocs.length === 0 && (
              <TableRow>
                <TableCell colSpan={3 + columns.length}>
                  <Typography color="text.secondary">
                    {query ? 'No documents match your search.' : t('documents.noDocs')}
                  </Typography>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mt: 1 }}>
        <Chip size="small" label={`${filtered.length} ${t('documents.docs').toLowerCase()}`} />
        {pageCount > 1 && (
          <Pagination
            size="small"
            count={pageCount}
            page={safePage}
            onChange={(_e, p) => setPage(p)}
          />
        )}
      </Box>
    </Box>
  );
}
