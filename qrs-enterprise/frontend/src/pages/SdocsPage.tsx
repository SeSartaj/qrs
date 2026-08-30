import { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material';
import { api, type SdocRecord } from '../lib/api';

interface Props {
  onSelectSdoc: (sdocId: string) => void;
}

export function SdocsPage({ onSelectSdoc }: Props) {
  const [sdocs, setSdocs] = useState<SdocRecord[]>([]);
  const [error, setError] = useState('');

  useEffect(() => {
    api
      .listSdocs()
      .then(setSdocs)
      .catch((e) => setError(e.message));
  }, []);

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Documents
      </Typography>
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>SDoc ID</TableCell>
              <TableCell>TCert</TableCell>
              <TableCell>Signed by</TableCell>
              <TableCell>Issued at</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {sdocs.map((s) => (
              <TableRow
                key={s.id}
                hover
                sx={{ cursor: 'pointer' }}
                onClick={() => onSelectSdoc(s.sdoc_id)}
              >
                <TableCell>{s.sdoc_id}</TableCell>
                <TableCell>{s.tcert_id}</TableCell>
                <TableCell>{s.signed_by ?? '—'}</TableCell>
                <TableCell>{new Date(s.issued_at * 1000).toLocaleString()}</TableCell>
              </TableRow>
            ))}
            {sdocs.length === 0 && (
              <TableRow>
                <TableCell colSpan={4}>No documents yet.</TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}