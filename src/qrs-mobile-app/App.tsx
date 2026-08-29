/**
 * QRS Verifier — mobile app entry.
 *
 * A React Native (Expo) app built on `qrs-core` for verifying signed documents
 * (SDoc) offline. Trust management (pin / CA / distrust) is protected by an admin
 * password configured on first launch.
 */
import React from 'react';
import { I18nManager } from 'react-native';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import { StatusBar } from 'expo-status-bar';
import { GestureHandlerRootView } from 'react-native-gesture-handler';

// Set up crypto (getRandomValues + crypto.subtle on native) before anything uses it.
import './lib/crypto';
import { setContextHandlers } from './lib/runtime';
import { buildContextHandlers } from './lib/contextHandlers';
import { AppNavigator, navigationRef } from './navigation/AppNavigator';
import { setupDeepLinking } from './lib/deeplink';
import { getSettings, isRtl } from './lib/settings';

// Apply the persisted RTL preference before the UI mounts. On native this may
// require a reload to take full effect; on web it applies immediately.
void getSettings().then((s) => {
  const rtl = isRtl(s.language);
  if (I18nManager.isRTL !== rtl) {
    I18nManager.forceRTL(rtl);
    I18nManager.allowRTL(true);
  }
});

// Wire interactive verification inputs to the UI:
//   - secrets  → the SecretPromptHost dialog,
//   - location → expo-location (permission + current position for comparison),
//   - online objects (attachments) → fetched from the issuing TCert's server.
void buildContextHandlers().then(setContextHandlers);

// Open `qrs://` links (scanning a QR with the OS camera) directly in this app.
setupDeepLinking(navigationRef);

export default function App() {
  return (
    <GestureHandlerRootView style={{ flex: 1 }}>
      <SafeAreaProvider>
        <StatusBar style="auto" />
        {/* Keep every navigator screen above Android's system navigation area. */}
        <SafeAreaView style={{ flex: 1 }} edges={['bottom']}>
          <AppNavigator />
        </SafeAreaView>
      </SafeAreaProvider>
    </GestureHandlerRootView>
  );
}
