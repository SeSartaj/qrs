import { createTheme } from '@mui/material/styles';

export function buildTheme(direction: 'ltr' | 'rtl') {
  return createTheme({
    direction,
    palette: {
      mode: 'dark',
      primary: { main: '#4f8cff' },
      secondary: { main: '#a78bfa' },
      success: { main: '#34c98f' },
      warning: { main: '#f5b85c' },
      error: { main: '#ef6a6a' },
      background: { default: '#0f1216', paper: '#171c22' },
    },
    shape: { borderRadius: 10 },
    typography: {
      fontFamily: `'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif`,
      h6: { fontWeight: 700 },
    },
    components: {
      MuiCard: { styleOverrides: { root: { border: '1px solid #232a33' } } },
      MuiTextField: { defaultProps: { size: 'small' } },
    },
  });
}

