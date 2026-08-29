import { useTranslation } from 'react-i18next';
import {
  Box,
  Drawer,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  MenuItem,
  Select,
  Toolbar,
  Typography,
  FormControl,
  InputLabel,
} from '@mui/material';
import type { ReactNode } from 'react';
import BadgeIcon from '@mui/icons-material/Badge';
import DescriptionIcon from '@mui/icons-material/Description';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import ShieldIcon from '@mui/icons-material/Shield';
import BlockIcon from '@mui/icons-material/Block';
import SettingsIcon from '@mui/icons-material/Settings';
import ArchiveIcon from '@mui/icons-material/Archive';
import { LANGUAGE_NAMES, setLanguage, type LanguageCode } from '../i18n';
import { CALENDAR_LABELS, setCalendar, useCalendar, type CalendarId } from '../calendarSetting';

/**
 * Top-level pages. `issue` (create TCert / manage keys) is deliberately kept out
 * of the main navigation — it is a one-off action reached from Settings.
 */
export type PageId = 'documents' | 'issue' | 'verify' | 'trust' | 'revocation' | 'settings' | 'archive';

export const NAV_ICONS: Record<PageId, ReactNode> = {
  documents: <DescriptionIcon />,
  issue: <BadgeIcon />,
  verify: <VerifiedUserIcon />,
  trust: <ShieldIcon />,
  revocation: <BlockIcon />,
  settings: <SettingsIcon />,
  archive: <ArchiveIcon />,
};

export const NAV_KEYS: Array<{ id: PageId; labelKey: string }> = [
  { id: 'documents', labelKey: 'nav.documents' },
  { id: 'verify', labelKey: 'nav.verify' },
  { id: 'trust', labelKey: 'nav.trust' },
  { id: 'revocation', labelKey: 'nav.revocation' },
  { id: 'settings', labelKey: 'nav.settings' },
];

const DRAWER_WIDTH = 260;

interface LayoutProps {
  page: PageId;
  onNavigate: (page: PageId) => void;
  children: ReactNode;
}

export function Layout({ page, onNavigate, children }: LayoutProps) {
  const { t, i18n } = useTranslation();
  const lang = (i18n.resolvedLanguage ?? 'en') as LanguageCode;
  const calendar = useCalendar();

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh' }}>
      <Drawer
        variant="permanent"
        sx={{
          width: DRAWER_WIDTH,
          flexShrink: 0,
          '& .MuiDrawer-paper': { width: DRAWER_WIDTH, boxSizing: 'border-box' },
        }}
      >
        <Toolbar>
          <Typography variant="h6" sx={{ fontWeight: 800, letterSpacing: 0.5 }}>
            QRS Desktop
          </Typography>
        </Toolbar>
        <List>
          {NAV_KEYS.map((item) => (
            <ListItemButton key={item.id} selected={page === item.id} onClick={() => onNavigate(item.id)}>
              <ListItemIcon>{NAV_ICONS[item.id]}</ListItemIcon>
              <ListItemText primary={t(item.labelKey)} />
            </ListItemButton>
          ))}
        </List>
        <Box sx={{ mt: 'auto', p: 2, display: 'flex', flexDirection: 'column', gap: 1 }}>
          <FormControl fullWidth size="small">
            <InputLabel>{t('nav.language')}</InputLabel>
            <Select value={lang} label={t('nav.language')} onChange={(e) => setLanguage(e.target.value as LanguageCode)}>
              {(Object.keys(LANGUAGE_NAMES) as LanguageCode[]).map((code) => (
                <MenuItem key={code} value={code}>
                  {LANGUAGE_NAMES[code]}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl fullWidth size="small">
            <InputLabel>{t('nav.calendar')}</InputLabel>
            <Select
              value={calendar}
              label={t('nav.calendar')}
              onChange={(e) => setCalendar(e.target.value as CalendarId)}
            >
              {(Object.keys(CALENDAR_LABELS) as CalendarId[]).map((c) => (
                <MenuItem key={c} value={c}>
                  {CALENDAR_LABELS[c]}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Box>
      </Drawer>
      <Box component="main" sx={{ flexGrow: 1, p: 3, maxWidth: 1100 }}>
        {children}
      </Box>
    </Box>
  );
}
