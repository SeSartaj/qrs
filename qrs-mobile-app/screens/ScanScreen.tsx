/**
 * Scan tab: a full-screen QR scanner.
 *
 * A square scan frame keeps the camera focused on the code; the flashlight
 * helps in dim rooms (native only). Whatever is scanned is handled
 * intelligently — SDoc → verify, TCert → import, statement → apply,
 * bundle (e.g. TCert + CA attestation) → process all objects.
 * (Importing a `.qrs` file lives on the Process tab, not here.)
 */
import React, { useCallback, useState } from 'react';
import { Platform, StyleSheet, useWindowDimensions, View } from 'react-native';
import { ActivityIndicator, Appbar, Button, IconButton, Text, useTheme } from 'react-native-paper';
import { CameraView, useCameraPermissions } from 'expo-camera';
import { useFocusEffect } from '@react-navigation/native';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';
import type { RootStackParamList } from '../navigation/types';
import { processPayload, sdocPayload, type ProcessOutcome } from '../lib/process';
import { addHistory } from '../lib/history';
import { getSettings } from '../lib/settings';

type Nav = NativeStackNavigationProp<RootStackParamList, 'Tabs'>;

const MASK = 'rgba(0,0,0,0.5)';

export function ScanScreen({ navigation }: { navigation: Nav }) {
  const theme = useTheme();
  const { width } = useWindowDimensions();
  const [permission, requestPermission] = useCameraPermissions();
  const [scanned, setScanned] = useState(false);
  const [busy, setBusy] = useState(false);
  const [torchOn, setTorchOn] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Keep the scan square comfortable on any screen (clamp to 72% of the width).
  const frame = Math.min(width * 0.72, 300);

  const reset = useCallback((): void => {
    setScanned(false);
    setBusy(false);
    setError(null);
  }, []);

  // When the tab regains focus (e.g. coming back from a result screen), reset the
  // scan state so the camera is re-enabled and the "Processing…" overlay clears.
  useFocusEffect(
    useCallback(() => {
      reset();
    }, [reset])
  );

  const runProcess = async (raw: string): Promise<void> => {
    setBusy(true);
    setError(null);
    const sdoc = sdocPayload(raw);
    if (sdoc) {
      setBusy(false);
      setScanned(false);
      navigation.navigate('Result', { loading: true, raw: sdoc });
      return;
    }
    try {
      const outcome: ProcessOutcome = await processPayload(raw);
      if (outcome.kind === 'tcert-imported' && (await getSettings()).historyEnabled) {
        await addHistory({
          raw,
          documentName: outcome.documentName,
          issuerName: outcome.issuerName,
          verdict: 'stored',
          ts: Date.now(),
        });
      }
      if (outcome.kind === 'verified') navigation.navigate('Result', { result: outcome.result });
      else navigation.navigate('Processed', { outcome });
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not process the payload.');
    } finally {
      setBusy(false);
      setScanned(false);
    }
  };

  const handle = async (data: string): Promise<void> => {
    if (!data || scanned || busy) return;
    setScanned(true);
    await runProcess(data);
  };

  return (
    <View style={styles.root}>
      <Appbar.Header style={styles.appbar}>
        <Appbar.Content title="Scan a QR code" />
        {Platform.OS !== 'web' && (
          <IconButton
            icon={torchOn ? 'flashlight' : 'flashlight-off'}
            selected={torchOn}
            onPress={() => setTorchOn((v) => !v)}
            accessibilityLabel="Toggle flashlight"
          />
        )}
      </Appbar.Header>

      <View style={styles.cameraWrap}>
        {permission?.granted ? (
          <CameraView
            style={StyleSheet.absoluteFill}
            facing="back"
            enableTorch={torchOn}
            onBarcodeScanned={scanned ? undefined : ({ data }) => void handle(data)}
          />
        ) : (
          <View style={styles.center}>
            <Text variant="bodyLarge" style={styles.centerTitle}>
              Camera access is required to scan
            </Text>
            <Text variant="bodySmall" style={styles.centerSub}>
              Allow camera access to scan document, certificate, statement and
              bundle QR codes.
            </Text>
            <Button mode="contained" style={{ marginTop: 16 }} onPress={() => void requestPermission()}>
              Grant camera permission
            </Button>
          </View>
        )}

        {/* Dark mask with a transparent square scan frame */}
        <View pointerEvents="none" style={styles.mask}>
          <View style={[styles.maskBar, { flex: 1 }]} />
          <View style={{ flexDirection: 'row', height: frame }}>
            <View style={[styles.maskSide, { flex: 1 }]} />
            <View style={{ width: frame, height: frame }}>
              <View
                style={[
                  styles.corner,
                  { top: 0, left: 0, borderTopWidth: 3, borderLeftWidth: 3, borderTopLeftRadius: 18 },
                ]}
              />
              <View
                style={[
                  styles.corner,
                  { top: 0, right: 0, borderTopWidth: 3, borderRightWidth: 3, borderTopRightRadius: 18 },
                ]}
              />
              <View
                style={[
                  styles.corner,
                  { bottom: 0, left: 0, borderBottomWidth: 3, borderLeftWidth: 3, borderBottomLeftRadius: 18 },
                ]}
              />
              <View
                style={[
                  styles.corner,
                  { bottom: 0, right: 0, borderBottomWidth: 3, borderRightWidth: 3, borderBottomRightRadius: 18 },
                ]}
              />
            </View>
            <View style={[styles.maskSide, { flex: 1 }]} />
          </View>
          <View style={[styles.maskBar, { flex: 1 }]} />
        </View>

        {(scanned || busy) && (
          <View style={styles.overlay}>
            <ActivityIndicator color="#fff" />
            <Text style={styles.overlayText}>Processing…</Text>
          </View>
        )}
      </View>

      <View style={styles.footer}>
        <Text variant="bodySmall" style={[styles.hint, { color: theme.colors.onSurfaceVariant }]}>
          {torchOn ? 'Flashlight on' : 'Align the QR code inside the square'}
        </Text>
        {error ? (
          <View style={styles.errorBox}>
            <Text style={[styles.error, { color: theme.colors.error }]}>{error}</Text>
            <Button mode="text" onPress={reset}>
              Scan again
            </Button>
          </View>
        ) : null}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1 },
  appbar: { elevation: 0 },
  cameraWrap: { flex: 1, overflow: 'hidden', backgroundColor: '#000' },
  center: { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 24, backgroundColor: '#000' },
  centerTitle: { color: '#fff', marginBottom: 4 },
  centerSub: { color: 'rgba(255,255,255,0.7)', textAlign: 'center', lineHeight: 18 },
  mask: { position: 'absolute', top: 0, left: 0, right: 0, bottom: 0 },
  maskBar: { backgroundColor: MASK },
  maskSide: { backgroundColor: MASK },
  corner: {
    position: 'absolute',
    width: 30,
    height: 30,
    borderColor: '#fff',
  },
  overlay: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: 'rgba(0,0,0,0.55)',
  },
  overlayText: { color: '#fff', marginTop: 8 },
  footer: { padding: 16, alignItems: 'center' },
  hint: { textAlign: 'center' },
  errorBox: { marginTop: 12, alignItems: 'center' },
  error: { textAlign: 'center', marginBottom: 4 },
});
