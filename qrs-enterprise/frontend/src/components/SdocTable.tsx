import { useEffect, useMemo, useState } from 'react';
import {
  Box,
  Button,
  Card,
  Checkbox,
  Chip,
  FormControlLabel,
  Menu,
  MenuItem,
  Pagination,
  Select,
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
import type { SdocRecord } from '../lib/api';

const PAGE_SIZE_OPTIONS = [5, 20, 50, 100];

interface Props {
  docs: SdocRecord[];
  onOpen: (sdocId: string) => void;
}

function shortId(id: string): string {
  return id.length > 12 ? `${id.slice(0, 12)}…` : id;
}

function formatDate(epoch: number): string {
  return new Date(epoch * 1000).toLocaleString();
}

/**
 * A searchable, paginated SDoc table with a configurable column checklist.
 * Adapted from the qrs-desktop `SdocTable` component.
 */
export function SdocTable({ docs, onOpen }: Props) {
  const [query, setQuery] = useState('');
  const [columnMenu, setColumnMenu] = useState<null | HTMLElement>(null);
  const [hiddenColumns, setHiddenColumns] = useState<string[]>([]);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(PAGE_SIZE_OPTIONS[0]);

  const allColumns = ['sdoc_id', 'tcert_id', 'signed_by', 'issued_at'];

  const columns = useMemo(() => allColumns.filter((c) => !hiddenColumns.includes(c)), [hiddenColumns]);

  const toggleColumn = (name: string): void => {
    setHiddenColumns((prev) => (prev.includes(name) ? prev.filter((c) => c !== name) : [...prev, name]));
  };

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const chronological = [...docs].sort((a, b) => b.issued_at - a.issued_at);
    if (!q) return chronological;
    return chronological.filter((d) => {
      if (d.sdoc_id.toLowerCase().includes(q)) return true;
      if (d.tcert_id.toLowerCase().includes(q)) return true;
      if ((d.signed_by ?? '').toLowerCase().includes(q)) return true;
      if (formatDate(d.issued_at).toLowerCase().includes(q)) return true;
      return false;
    });
  }, [docs, query]);

  useEffect(() => {
    setPage(1);
  }, [query, docs]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const safePage = Math.min(page, pageCount);
  const pageDocs = filtered.slice((safePage - 1) * pageSize, safePage * pageSize);

  const labelFor = (name: string): string => {
    switch (name) {
      case 'sdoc_id':
        return 'SDoc ID';
      case 'tcert_id':
        return 'TCert';
      case 'signed_by':
        return 'Signed by';
      case 'issued_at':
        return 'Issued at';
      default:
        return name;
    }
  };

  const valueFor = (d: SdocRecord, name: string): string => {
    switch (name) {
      case 'sdoc_id':
        return shortId(d.sdoc_id);
      case 'tcert_id':
        return d.tcert_id;
      case 'signed_by':
        return d.signed_by ?? '—';
      case 'issued_at':
        return formatDate(d.issued_at);
      default:
        return '—';
    }
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', gap: 1, mb: 1 }}>
        <TextField
          size="small"
          fullWidth
          placeholder="Search by SDoc id, TCert, signer, or date…"
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
        <Select
          size="small"
          value={pageSize}
          onChange={(e) => {
            setPageSize(Number(e.target.value));
            setPage(1);
          }}
        >
          {PAGE_SIZE_OPTIONS.map((size) => (
            <MenuItem key={size} value={size}>
              {size} / page
            </MenuItem>
          ))}
        </Select>
        <Menu anchorEl={columnMenu} open={Boolean(columnMenu)} onClose={() => setColumnMenu(null)}>
          {allColumns.map((c) => (
            <MenuItem key={c} dense>
              <FormControlLabel
                control={
                  <Checkbox
                    size="small"
                    checked={!hiddenColumns.includes(c)}
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
              {columns.map((c) => (
                <TableCell key={c}>{labelFor(c)}</TableCell>
              ))}
            </TableRow>
          </TableHead>
          <TableBody>
            {pageDocs.map((d) => (
              <TableRow key={d.sdoc_id} hover sx={{ cursor: 'pointer' }} onClick={() => onOpen(d.sdoc_id)}>
                {columns.map((c) => (
                  <TableCell
                    key={c}
                    sx={
                      c === 'sdoc_id'
                        ? { fontFamily: 'monospace', fontSize: 12, color: 'primary.main' }
                        : c === 'issued_at'
                          ? { whiteSpace: 'nowrap' }
                          : { maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }
                    }
                  >
                    {valueFor(d, c)}
                  </TableCell>
                ))}
              </TableRow>
            ))}
            {pageDocs.length === 0 && (
              <TableRow>
                <TableCell colSpan={columns.length}>
                  <Typography color="text.secondary">
                    {query ? 'No documents match your search.' : 'No documents.'}
                  </Typography>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mt: 1 }}>
        <Chip size="small" label={`${filtered.length} documents`} />
        {pageCount > 1 && (
          <Pagination size="small" count={pageCount} page={safePage} onChange={(_e, p) => setPage(p)} />
        )}
      </Box>
    </Box>
  );
}