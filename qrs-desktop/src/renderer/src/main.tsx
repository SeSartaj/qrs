import { StrictMode, useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { CacheProvider } from '@emotion/react';
import createCache from '@emotion/cache';
import rtlPlugin from 'stylis-plugin-rtl';
import { prefixer } from 'stylis';
import { CssBaseline, ThemeProvider } from '@mui/material';
import App from './App';
import { buildTheme } from './theme';
import { isRtl } from './i18n';

function Root() {
  const [dir, setDir] = useState<'ltr' | 'rtl'>(() => (isRtl(document.documentElement.lang) ? 'rtl' : 'ltr'));

  useEffect(() => {
    const update = (): void => {
      const next = isRtl(document.documentElement.lang || 'en') ? 'rtl' : 'ltr';
      document.documentElement.dir = next;
      setDir(next);
    };
    // Re-evaluate when i18next changes the <html lang> attribute.
    const observer = new MutationObserver(update);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['lang'] });
    update();
    return () => observer.disconnect();
  }, []);

  const cache = useMemo(
    () =>
      createCache({
        key: dir === 'rtl' ? 'muirtl' : 'muiltr',
        stylisPlugins: dir === 'rtl' ? [prefixer, rtlPlugin] : undefined,
      }),
    [dir]
  );

  const theme = useMemo(() => buildTheme(dir), [dir]);

  return (
    <CacheProvider value={cache}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <App />
      </ThemeProvider>
    </CacheProvider>
  );
}

createRoot(document.getElementById('root') as HTMLElement).render(
  <StrictMode>
    <Root />
  </StrictMode>
);

