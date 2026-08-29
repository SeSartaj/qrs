/**
 * App theme: clean, verification-focused. Primary is the "verified blue" used for
 * trust badges; success/error/warning map to a clear verdict palette.
 */
import { MD3LightTheme, MD3DarkTheme } from 'react-native-paper';

export const VERIFIED_BLUE = '#1D9BF0'; // Twitter/X verified blue
export const SUCCESS = '#1E8E3E';
export const ERROR = '#D93025';
export const WARNING = '#E37400';

const base = {
  colors: {
    primary: VERIFIED_BLUE,
    secondary: '#0B57D0',
    tertiary: '#00639B',
    error: ERROR,
    success: SUCCESS,
    warning: WARNING,
  },
};

export const lightTheme = {
  ...MD3LightTheme,
  ...base,
  colors: {
    ...MD3LightTheme.colors,
    ...base.colors,
  },
};

export const darkTheme = {
  ...MD3DarkTheme,
  ...base,
  colors: {
    ...MD3DarkTheme.colors,
    ...base.colors,
    primary: '#8AB4F8',
    secondary: '#A8C7FA',
  },
};

export function verdictColor(verdict: string, isDark: boolean): string {
  if (verdict === 'valid') return SUCCESS;
  if (verdict === 'invalid') return ERROR;
  return WARNING;
}
