/**
 * Verification history: the list of previously processed payloads, persisted in
 * AsyncStorage. Shared by the Process tab ("Recently verified") and the History
 * tab (full list).
 */
import AsyncStorage from '@react-native-async-storage/async-storage';

const HISTORY_KEY = 'qrs.verified-history';
const MAX_ENTRIES = 200;

export interface HistoryEntry {
  raw: string;
  documentName?: string;
  issuerName?: string;
  verdict: string;
  ts: number;
}

export async function loadHistory(): Promise<HistoryEntry[]> {
  try {
    const raw = await AsyncStorage.getItem(HISTORY_KEY);
    return raw ? (JSON.parse(raw) as HistoryEntry[]) : [];
  } catch {
    return [];
  }
}

export async function addHistory(entry: HistoryEntry): Promise<void> {
  const list = await loadHistory();
  list.unshift(entry);
  await AsyncStorage.setItem(HISTORY_KEY, JSON.stringify(list.slice(0, MAX_ENTRIES)));
}

export async function clearHistory(): Promise<void> {
  await AsyncStorage.removeItem(HISTORY_KEY);
}

export function historyVerdictColor(verdict: string): string {
  if (verdict === 'valid') return '#1E8E3E';
  if (verdict === 'invalid') return '#D93025';
  return '#E37400';
}
