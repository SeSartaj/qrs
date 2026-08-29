import { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  FormControl,
  InputLabel,
  List,
  ListItem,
  ListItemText,
  MenuItem,
  Select,
  Typography,
} from '@mui/material';
import BadgeIcon from '@mui/icons-material/Badge';
import LockIcon from '@mui/icons-material/Lock';
import LockOpenIcon from '@mui/icons-material/LockOpen';
import { useTranslation } from 'react-i18next';
import type { AppInfo } from '@shared/types';
import type { PageId } from '../components/Layout';
import { qrs, safe } from '../api';
import { CALENDAR_LABELS, setCalendar, useCalendar, type CalendarId } from '../calendarSetting';

const isDev = import.meta.env.DEV;

export function SettingsPage({ onNavigate }: { onNavigate: (p: PageId) => void }) {
  const { t } = useTranslation();
  const [info, setInfo] = useState<AppInfo | null>(null);
  const calendar = useCalendar();

  useEffect(() => {
    void (async () => {
      const infoRes = await safe(qrs().app.getInfo());
      if (infoRes.ok) setInfo(infoRes.value);
    })();
  }, []);

  const rows = info
    ? [
        { label: t('settings.appVersion'), value: info.version },
        { label: t('settings.electron'), value: info.electron },
        { label: t('settings.chromium'), value: info.chrome },
        { label: t('settings.node'), value: info.node },
        { label: t('settings.platform'), value: info.platform },
        { label: t('settings.dataDir'), value: info.dataDir },
        {
          label: t('settings.privateKeys'),
          value:
            info.keyProtection?.kind === 'hardware-tpm' || info.keyProtection?.kind === 'hardware-se'
              ? 'Hardware-backed (TPM / Secure Enclave)'
              : info.secureKeys
                ? t('settings.keysEncrypted')
                : t('settings.keysPlain'),
        },
      ]
    : [];

  return (
    <Box>
      <Typography variant="h5" sx={{ mb: 3 }}>
        {t('settings.title')}
      </Typography>
      {isDev && (
        <Alert severity="info" sx={{ mb: 2 }}>
          {t('settings.devHint')}
        </Alert>
      )}

      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
            <BadgeIcon color="primary" />
            <Typography variant="h6">{t('settings.keysCerts')}</Typography>
          </Box>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            {t('settings.keysCertsHint')}
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            <Button variant="contained" startIcon={<BadgeIcon />} onClick={() => onNavigate('issue')}>
              {t('settings.createCert')}
            </Button>
          </Box>
        </CardContent>
      </Card>

      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Typography variant="h6" sx={{ mb: 1 }}>TCert archive</Typography>
          <Button variant="outlined" onClick={() => onNavigate('archive')}>Open archive list</Button>
        </CardContent>
      </Card>

      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Typography variant="h6" sx={{ mb: 1 }}>
            {t('nav.calendar')}
          </Typography>
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
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            Dates are always stored as Gregorian on the protocol; you enter them in your preferred calendar.
          </Typography>
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
            {info?.secureKeys ? <LockIcon color="success" fontSize="small" /> : <LockOpenIcon color="warning" fontSize="small" />}
            <Typography variant="h6">{t('settings.about')}</Typography>
          </Box>
          <List dense>
            {rows.map((r) => (
              <ListItem key={r.label} disableGutters>
                <ListItemText
                  primary={r.label}
                  secondary={r.value}
                  primaryTypographyProps={{ variant: 'body2' }}
                  secondaryTypographyProps={{ fontFamily: 'monospace' }}
                />
              </ListItem>
            ))}
          </List>
          {info?.keyProtection?.kind === 'plaintext' && (
            <Alert severity="warning" sx={{ mt: 1.5 }}>
              Private keys are NOT encrypted at rest on this machine. {info.keyProtection.note}
            </Alert>
          )}
          {info?.keyProtection && info.keyProtection.kind !== 'plaintext' && (
            <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
              {info.keyProtection.note}
            </Typography>
          )}
          <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
            {t('settings.note')}
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
}
