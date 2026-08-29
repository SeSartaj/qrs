import { Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, Typography } from '@mui/material';

interface Props {
  open: boolean;
  title: string;
  /** JSON-safe decoded object (from `window.qrs.objects.decode`). */
  json?: unknown;
  diagnostic?: string;
  onClose: () => void;
}

/** Dev-only: shows plaintext data alongside the complete COSE wire structure. */
export function StructureDialog({ open, title, json, diagnostic, onClose }: Props) {
  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent dividers>
        {json === undefined ? (
          <Typography color="text.secondary">Loading…</Typography>
        ) : (
          <>
          {diagnostic && <Box component="pre" sx={{ m: 0, mb: 2, p: 2, bgcolor: 'background.default', borderRadius: 1, fontSize: 12, lineHeight: 1.6, overflow: 'auto', maxHeight: '45vh', fontFamily: 'monospace', whiteSpace: 'pre' }}>{diagnostic}</Box>}
          <Box
            component="pre"
            sx={{
              m: 0,
              p: 2,
              bgcolor: 'background.default',
              borderRadius: 1,
              fontSize: 12,
              lineHeight: 1.6,
              overflow: 'auto',
              maxHeight: '60vh',
              fontFamily: 'monospace',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
            }}
          >
            {JSON.stringify(json, null, 2)}
          </Box>
          </>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}
