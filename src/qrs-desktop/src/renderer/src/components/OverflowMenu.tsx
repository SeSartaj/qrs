import { useState } from 'react';
import { IconButton, Menu, MenuItem } from '@mui/material';
import MoreVertIcon from '@mui/icons-material/MoreVert';

export interface OverflowAction { label: string; onClick: () => void; color?: 'inherit' | 'error'; }

export function OverflowMenu({ actions, disabled = false }: { actions: OverflowAction[]; disabled?: boolean }) {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  return <>
    <IconButton size="small" disabled={disabled} onClick={(e) => { e.stopPropagation(); setAnchor(e.currentTarget); }}><MoreVertIcon /></IconButton>
    <Menu anchorEl={anchor} open={Boolean(anchor)} onClose={() => setAnchor(null)}>
      {actions.map((action) => <MenuItem key={action.label} sx={{ color: action.color }} onClick={(e) => { e.stopPropagation(); setAnchor(null); action.onClick(); }}>{action.label}</MenuItem>)}
    </Menu>
  </>;
}
