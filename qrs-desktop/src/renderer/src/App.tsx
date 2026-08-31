import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { Alert, Snackbar } from '@mui/material';
import { Layout, type PageId } from './components/Layout';
import { ContextDialogHost } from './components/ContextDialogHost';
import { IssuerPage } from './pages/IssuerPage';
import { DocumentsPage } from './pages/DocumentsPage';
import { VerifyPage } from './pages/VerifyPage';
import { TrustPage } from './pages/TrustPage';
import { RevocationPage } from './pages/RevocationPage';
import { SettingsPage } from './pages/SettingsPage';
import { ArchivePage } from './pages/ArchivePage';
import { GlobalPasswordPrompt } from './components/GlobalPasswordPrompt';
import { qrs } from './api';

export default function App() {
  const [page, setPage] = useState<PageId>('documents');
  const [notice, setNotice] = useState<{ severity: 'success' | 'error' | 'info'; text: string } | null>(null);
  const [pendingVerify, setPendingVerify] = useState<string | null>(null);
  const [initialTcertId, setInitialTcertId] = useState<string | null>(null);
  const [globalPasswordLocked, setGlobalPasswordLocked] = useState(false);

  useEffect(() => {
    void qrs().keys.passwordStatus().then((status) => {
      if (status.configured && !status.unlocked) setGlobalPasswordLocked(true);
    }).catch(() => undefined);
  }, []);

  // Allow the host (screenshot tooling) to navigate pages.
  useEffect(() => {
    (window as unknown as { __qrsGo?: (p: string) => void }).__qrsGo = (p) => {
      if (p === 'documents' || p === 'issue' || p === 'verify' || p === 'trust' || p === 'revocation' || p === 'settings' || p === 'archive') {
        setPage(p);
      }
    };
  }, []);

  const showNotice = (severity: 'success' | 'error' | 'info', text: string): void =>
    setNotice({ severity, text });

  const handleTcertCreated = useCallback((tcertId: string): void => {
    setInitialTcertId(tcertId);
    setPage('documents');
  }, []);

  const clearInitialTcert = useCallback((): void => setInitialTcertId(null), []);

  const pages: Record<PageId, ReactNode> = {
    documents: (
      <DocumentsPage
        showNotice={showNotice}
        initialTcertId={initialTcertId}
        onInitialTcertOpened={clearInitialTcert}
        onVerify={(b64) => {
          setPendingVerify(b64);
          setPage('verify');
        }}
      />
    ),
    issue: <IssuerPage showNotice={showNotice} onCreated={handleTcertCreated} onBack={() => setPage('settings')} />,
    verify: (
      <VerifyPage
        initialBytesB64={pendingVerify ?? undefined}
        onConsumed={() => setPendingVerify(null)}
        showNotice={showNotice}
      />
    ),
    trust: <TrustPage showNotice={showNotice} />,
    revocation: <RevocationPage showNotice={showNotice} />,
    settings: <SettingsPage onNavigate={setPage} />,
    archive: <ArchivePage onNavigate={setPage} />,
  };

  return (
    <>
      <Layout page={page} onNavigate={setPage}>
        {pages[page]}
      </Layout>
      <ContextDialogHost />
      <GlobalPasswordPrompt open={globalPasswordLocked} onUnlocked={() => setGlobalPasswordLocked(false)} />
      <Snackbar
        open={notice !== null}
        autoHideDuration={5000}
        onClose={() => setNotice(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity={notice?.severity ?? 'info'} variant="filled" onClose={() => setNotice(null)}>
          {notice?.text}
        </Alert>
      </Snackbar>
    </>
  );
}
