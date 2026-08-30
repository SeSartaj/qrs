import { Component, useState, type ErrorInfo, type ReactNode } from 'react';
import { Alert, Box, Button, CssBaseline, ThemeProvider, createTheme } from '@mui/material';
import { AuthProvider, useAuth } from './lib/auth';
import { NoticeProvider } from './lib/notice';
import { Layout, type PageId } from './components/Layout';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { SignPage } from './pages/SignPage';
import { CaPage } from './pages/CaPage';
import { SdocsPage } from './pages/SdocsPage';
import { AdminPage } from './pages/AdminPage';
import { TcertDetailPage } from './pages/TcertDetailPage';
import { SdocDetailPage } from './pages/SdocDetailPage';

const theme = createTheme({
  palette: {
    mode: 'dark',
  },
});

interface ErrorBoundaryProps { children: ReactNode }
interface ErrorBoundaryState { error: Error | null; stack: string }

/** Keep one malformed schema/date value from blanking the whole SPA. */
class AppErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null, stack: '' };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error, stack: '' };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('QRS Enterprise UI error', error, info);
    this.setState({ stack: info.componentStack || '' });
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">
          This page could not be rendered. Please reload and try again.
          <Box component="pre" sx={{ whiteSpace: 'pre-wrap', mt: 1 }}>
            {this.state.error.message}
          </Box>
          {this.state.stack && (
            <Box component="pre" sx={{ whiteSpace: 'pre-wrap', mt: 1, fontSize: 12, color: 'text.secondary' }}>
              {this.state.stack}
            </Box>
          )}
        </Alert>
        <Button sx={{ mt: 2 }} variant="outlined" onClick={() => window.location.reload()}>
          Reload
        </Button>
      </Box>
    );
  }
}

function Shell() {
  const { user, loading } = useAuth();
  const [page, setPage] = useState<PageId>('dashboard');
  const [selectedTcert, setSelectedTcert] = useState<number | null>(null);
  const [selectedSdoc, setSelectedSdoc] = useState<string | null>(null);

  if (loading) return null;
  if (!user) return <LoginPage />;

  const navigate = (p: PageId) => {
    setPage(p);
    setSelectedTcert(null);
    setSelectedSdoc(null);
  };

  // Detail views take precedence over their parent list pages.
  if (selectedTcert !== null) {
    return (
      <Layout page="dashboard" onNavigate={navigate}>
        <TcertDetailPage
          tcertId={selectedTcert}
          onBack={() => setSelectedTcert(null)}
          onOpenSdoc={(sdocId) => {
            setSelectedTcert(null);
            setSelectedSdoc(sdocId);
          }}
        />
      </Layout>
    );
  }
  if (selectedSdoc !== null) {
    return (
      <Layout page="sdocs" onNavigate={navigate}>
        <SdocDetailPage sdocId={selectedSdoc} onBack={() => setSelectedSdoc(null)} />
      </Layout>
    );
  }

  return (
    <Layout page={page} onNavigate={navigate}>
      {page === 'dashboard' && <DashboardPage onSelectTcert={setSelectedTcert} />}
      {page === 'sign' && <SignPage />}
      {page === 'ca' && <CaPage />}
      {page === 'sdocs' && <SdocsPage onSelectSdoc={setSelectedSdoc} />}
      {page === 'admin' && <AdminPage />}
    </Layout>
  );
}

export default function App() {
  return (
    <AppErrorBoundary>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <AuthProvider>
          <NoticeProvider>
            <Shell />
          </NoticeProvider>
        </AuthProvider>
      </ThemeProvider>
    </AppErrorBoundary>
  );
}
