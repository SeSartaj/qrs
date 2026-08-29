/**
 * OS-level deep linking for `qrs://` URLs.
 *
 * Scanning a QR with the OS camera (or tapping a `qrs://v1/...` link) opens this
 * app with the payload URL. We feed the URL straight into `processPayload`
 * (qrs-core strips the `qrs://v1/...` prefix) and navigate to the existing
 * Result / Processed screens. Both cold starts (`getInitialURL`) and warm starts
 * (`addEventListener`) are handled.
 */
import * as Linking from 'expo-linking';
import { File as ExpoFile } from 'expo-file-system';
import { Alert } from 'react-native';
import type { NavigationContainerRefWithCurrent } from '@react-navigation/native';
import type { RootStackParamList } from '../navigation/types';
import { processPayload } from './process';

type NavRef = NavigationContainerRefWithCurrent<RootStackParamList>;

let navRef: NavRef | null = null;
let subscription: { remove(): void } | null = null;

async function consume(url: string | null): Promise<void> {
  if (!url) return;
  if (!navRef?.isReady()) return;
  try {
    // Android/iOS may deliver an opened .qrs document as a file/content URI.
    // Read the plain-text container before sending it through the normal parser.
    const payload = url.startsWith('file://') || url.startsWith('content://')
      ? await new ExpoFile(url).text()
      : url;
    const outcome = await processPayload(payload);
    if (outcome.kind === 'verified') navRef.navigate('Result', { result: outcome.result });
    else navRef.navigate('Processed', { outcome });
  } catch (e) {
    Alert.alert('Invalid QR code', e instanceof Error ? e.message : 'Could not process this QR code.');
  }
}

/** Register the deep-link handler. Safe to call once; the ref may be set later. */
export function setupDeepLinking(ref: NavRef): void {
  navRef = ref;
  if (subscription) return;
  void Linking.getInitialURL().then(consume);
  subscription = Linking.addEventListener('url', ({ url }) => void consume(url));
}
