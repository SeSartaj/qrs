/**
 * Attachment display for a verification result.
 *
 * OFFLINE-FIRST: never auto-downloads. Loads file metadata (contentType + size)
 * from the issuing cert's distribution mirrors, shows it, and fetches the file
 * body on demand when the user taps Download/Open. On native the saved path is
 * shown so the file is easy to find; on web it triggers a browser download.
 */
import React, { useCallback, useEffect, useState } from 'react';
import { ActivityIndicator, Alert, Image, Linking, Platform, StyleSheet, View } from 'react-native';
import { Button, Text } from 'react-native-paper';
import * as FileSystem from 'expo-file-system/legacy';
import { getQrs } from '../lib/runtime';
import {
  fetchAttachmentContent,
  attachmentDataUri,
  extFor,
  fmtSize,
} from '../lib/attachment';

interface Props {
  /** Compact hash + size signed into the SDoc attachment field. */
  reference: string | { hash: string; size?: number };
  /** MIME type declared by the signed TCert schema. */
  contentType: string;
  /** Issuing TCert id → used to resolve the distribution mirrors. */
  tcertId: string;
}

export function AttachmentFieldView({ reference, contentType, tcertId }: Props) {
  const id = typeof reference === 'string' ? reference : reference.hash;
  const [status, setStatus] = useState<'ok' | 'missing' | 'error'>('ok');
  const [dataUri, setDataUri] = useState<string | null>(null);
  const [loadingContent, setLoadingContent] = useState(false);
  const [savedPath, setSavedPath] = useState<string | null>(null);
  const size = typeof reference === 'string' ? undefined : reference.size;
  const isImage = /^image\//.test(contentType);
  const previewableImage = isImage && size !== undefined && size <= 500 * 1024;

  /** Fetch the file body on demand (only when the user taps a button). */
  const loadContent = useCallback(async (): Promise<string | null> => {
    if (dataUri) return dataUri;
    setLoadingContent(true);
    try {
      const qrs = getQrs();
      const endpoints = await qrs.endpoints.effectiveEndpoints(tcertId);
      const att = await fetchAttachmentContent(qrs, id, contentType, endpoints);
      if (!att) {
        setStatus('missing');
        return null;
      }
      const uri = attachmentDataUri(att.contentType, att.content);
      setDataUri(uri);
      return uri;
    } finally {
      setLoadingContent(false);
    }
  }, [reference, contentType, tcertId, dataUri]);

  useEffect(() => {
    if (previewableImage) void loadContent();
  }, [loadContent, previewableImage]);

  const save = async (): Promise<string | null> => {
    const uri = await loadContent();
    if (!uri || Platform.OS === 'web') return uri;
    const path = `${FileSystem.documentDirectory ?? ''}${id}.${extFor(contentType)}`;
    const b64 = uri.split(',')[1] ?? '';
    await FileSystem.writeAsStringAsync(path, b64, { encoding: FileSystem.EncodingType.Base64 });
    setSavedPath(path);
    return path;
  };

  const open = async (): Promise<void> => {
    const uri = savedPath ? `file://${savedPath.replace(/^file:\/\//, '')}` : await save();
    if (!uri) {
      Alert.alert('Open failed', 'Attachment unavailable (offline or not found on the server)');
      return;
    }
    try {
      if (Platform.OS === 'web') {
        // Browser download via a temporary anchor element.
        const g = globalThis as unknown as {
          document?: {
            createElement(tag: string): {
              href: string;
              download: string;
              click(): void;
              remove(): void;
            };
            body?: { appendChild(el: unknown): void };
          };
        };
        const doc = g.document;
        if (doc) {
          const a = doc.createElement('a');
          a.href = uri;
          a.download = `${id}.${extFor(contentType)}`;
          doc.body?.appendChild(a);
          a.click();
          a.remove();
        }
        return;
      }
      const contentUri = Platform.OS === 'android' ? await FileSystem.getContentUriAsync(savedPath ?? uri) : savedPath ?? uri;
      await Linking.openURL(contentUri);
    } catch (e) {
      Alert.alert('Open failed', e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <View style={styles.wrap}>
      {status === 'missing' && (
        <Text variant="bodySmall" style={{ opacity: 0.7 }}>
          Attachment unavailable (offline or not found on the server)
        </Text>
      )}
      {status === 'error' && <Text variant="bodySmall">Attachment could not be loaded.</Text>}
      {status === 'ok' && (
        <View style={styles.row}>
          <Text variant="bodySmall" style={{ opacity: 0.8 }}>
            {contentType} · {fmtSize(size)}
          </Text>
          {loadingContent ? <ActivityIndicator accessibilityLabel="Loading attachment" /> : null}
          <Button compact icon="download" disabled={loadingContent} onPress={() => void save()}>{'Download'}</Button>
          <Button compact icon="open-in-new" disabled={loadingContent} onPress={() => void open()}>{'Open'}</Button>
        </View>
      )}
      {status === 'ok' && previewableImage && dataUri && (
        <Image source={{ uri: dataUri }} style={styles.image} resizeMode="contain" />
      )}
      {savedPath ? (
        <Text variant="labelSmall" style={styles.path}>
          {savedPath}
        </Text>
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: { marginTop: 4, marginBottom: 4 },
  row: { flexDirection: 'row', alignItems: 'center', gap: 8, marginTop: 2 },
  image: { width: '100%', height: 220, marginTop: 4, borderRadius: 6 },
  path: { marginTop: 4, opacity: 0.6 },
});
