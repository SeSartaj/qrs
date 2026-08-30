import { createContext, useContext, useState, type ReactNode } from 'react';
import { Alert, Snackbar } from '@mui/material';

type Severity = 'success' | 'error' | 'info';

interface NoticeState {
  showNotice: (severity: Severity, text: string) => void;
}

const NoticeContext = createContext<NoticeState>({ showNotice: () => {} });

export function NoticeProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const [severity, setSeverity] = useState<Severity>('info');
  const [text, setText] = useState('');

  const showNotice = (s: Severity, t: string) => {
    setSeverity(s);
    setText(t);
    setOpen(true);
  };

  return (
    <NoticeContext.Provider value={{ showNotice }}>
      {children}
      <Snackbar open={open} autoHideDuration={4000} onClose={() => setOpen(false)}>
        <Alert severity={severity} onClose={() => setOpen(false)} sx={{ width: '100%' }}>
          {text}
        </Alert>
      </Snackbar>
    </NoticeContext.Provider>
  );
}

export function useNotice() {
  return useContext(NoticeContext);
}