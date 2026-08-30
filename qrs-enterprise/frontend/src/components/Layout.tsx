import {
  AppBar,
  Box,
  Drawer,
  IconButton,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Toolbar,
  Tooltip,
  Typography,
} from '@mui/material';
import type { ReactNode } from 'react';
import DescriptionIcon from '@mui/icons-material/Description';
import ShieldIcon from '@mui/icons-material/Shield';
import SettingsIcon from '@mui/icons-material/Settings';
import LogoutIcon from '@mui/icons-material/Logout';
import { useAuth } from '../lib/auth';

export type PageId = 'dashboard' | 'sign' | 'ca' | 'sdocs' | 'admin' | 'settings';

export const NAV_ITEMS: Array<{ id: PageId; label: string; icon: ReactNode }> = [
  { id: 'dashboard', label: 'Dashboard', icon: <DescriptionIcon /> },
  { id: 'ca', label: 'CA operations', icon: <ShieldIcon /> },
  { id: 'sdocs', label: 'Documents', icon: <DescriptionIcon /> },
  { id: 'admin', label: 'Admin', icon: <SettingsIcon /> },
];

const DRAWER_WIDTH = 260;

interface LayoutProps {
  page: PageId;
  onNavigate: (page: PageId) => void;
  children: ReactNode;
}

export function Layout({ page, onNavigate, children }: LayoutProps) {
  const { user, logout } = useAuth();
  return (
    <Box sx={{ display: 'flex' }}>
      <AppBar position="fixed" sx={{ zIndex: (t) => t.zIndex.drawer + 1 }}>
        <Toolbar>
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            QRS Enterprise
          </Typography>
          <Typography variant="body2" sx={{ mr: 2 }}>
            {user?.username} ({user?.role})
          </Typography>
          <Tooltip title="Sign out">
            <IconButton onClick={() => logout()} color="inherit" edge="end">
              <LogoutIcon />
            </IconButton>
          </Tooltip>
        </Toolbar>
      </AppBar>
      <Drawer
        variant="permanent"
        sx={{
          width: DRAWER_WIDTH,
          flexShrink: 0,
          [`& .MuiDrawer-paper`]: { width: DRAWER_WIDTH, boxSizing: 'border-box' },
        }}
      >
        <Toolbar />
        <Box sx={{ overflow: 'auto' }}>
          <List>
            {NAV_ITEMS.map((item) => (
              <ListItemButton
                key={item.id}
                selected={page === item.id}
                onClick={() => onNavigate(item.id)}
              >
                <ListItemIcon>{item.icon}</ListItemIcon>
                <ListItemText primary={item.label} />
              </ListItemButton>
            ))}
          </List>
        </Box>
      </Drawer>
      <Box component="main" sx={{ flexGrow: 1, p: 3 }}>
        <Toolbar />
        {children}
      </Box>
    </Box>
  );
}