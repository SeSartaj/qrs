import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Box,
  Drawer,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Toolbar,
  Typography,
  IconButton,
} from '@mui/material';
import type { ReactNode } from 'react';
import BadgeIcon from '@mui/icons-material/Badge';
import DescriptionIcon from '@mui/icons-material/Description';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import ShieldIcon from '@mui/icons-material/Shield';
import BlockIcon from '@mui/icons-material/Block';
import SettingsIcon from '@mui/icons-material/Settings';
import ArchiveIcon from '@mui/icons-material/Archive';
import MenuOpenIcon from '@mui/icons-material/MenuOpen';
import MenuIcon from '@mui/icons-material/Menu';
import { qrs, safe } from '../api';

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
  const { t } = useTranslation();
  const [collapsed, setCollapsed] = useState(false);
  useEffect(() => { void safe(qrs().config.get()).then((result) => { if (result.ok) setCollapsed(result.value.sidebarCollapsed === true); }); }, []);
  const toggleSidebar = (): void => {
    const next = !collapsed;
    setCollapsed(next);
    void safe(qrs().config.get()).then((result) => { if (result.ok) void qrs().config.set({ ...result.value, sidebarCollapsed: next }); });
  };

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh' }}>
      <Drawer
        variant="permanent"
        sx={{
          width: collapsed ? 72 : DRAWER_WIDTH,
          flexShrink: 0,
          '& .MuiDrawer-paper': { width: collapsed ? 72 : DRAWER_WIDTH, boxSizing: 'border-box', overflowX: 'hidden' },
        }}
      >
        <Toolbar sx={collapsed ? { px: 0, justifyContent: 'center' } : undefined}>
          {!collapsed && <Typography variant="h6" sx={{ fontWeight: 800, letterSpacing: 0.5 }}>QRS Desktop</Typography>}
          <IconButton aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} onClick={toggleSidebar} sx={{ ml: collapsed ? 0 : 'auto' }}>
            {collapsed ? <MenuIcon /> : <MenuOpenIcon />}
          </IconButton>
        </Toolbar>
        <List>
          {NAV_KEYS.map((item) => (
            <ListItemButton key={item.id} selected={page === item.id} onClick={() => onNavigate(item.id)} sx={collapsed ? { px: 0, justifyContent: 'center' } : undefined}>
              <ListItemIcon sx={{ minWidth: collapsed ? 0 : 40 }}>{NAV_ICONS[item.id]}</ListItemIcon>
              {!collapsed && <ListItemText primary={t(item.labelKey)} />}
            </ListItemButton>
          ))}
        </List>
      </Drawer>
      <Box component="main" sx={{ flexGrow: 1, p: 3, maxWidth: 1100 }}>
        {children}
      </Box>
    </Box>
  );
}
