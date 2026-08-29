/**
 * `.qrs` file import.
 *
 * A `.qrs` file is a plain-text container holding a transfer payload
 * (`qrs://v1/<type>/<base64url>` or `qrs://v1/bundle/…`). This helper picks such a
 * file (shared via WhatsApp/email/USB from the desktop app) and reads its text so
 * the caller can feed it straight into `processPayload`.
 */
import * as DocumentPicker from 'expo-document-picker';
import { File as ExpoFile } from 'expo-file-system';
import { Platform } from 'react-native';

export interface PickedQrsFile {
  name: string;
  text: string;
}

export interface PickResult {
  canceled: boolean;
  file?: PickedQrsFile;
  error?: string;
}

/**
 * Open the system file picker, read the selected file as UTF-8 text and return it.
 * Works on web (reads the browser `File`) and on native (reads the copied cache
 * file via `expo-file-system`).
 */
export async function pickQrsFile(): Promise<PickResult> {
  try {
    const result = await DocumentPicker.getDocumentAsync({
      type: ['text/plain', 'application/octet-stream', 'application/json', '*/*'],
      copyToCacheDirectory: true,
      multiple: false,
    });
    if (result.canceled || !result.assets || result.assets.length === 0) {
      return { canceled: true };
    }
    const asset = result.assets[0];
    let text: string;
    if (Platform.OS === 'web') {
      const webFile = (asset as unknown as { file?: Blob }).file;
      if (!webFile) throw new Error('No file content available on web.');
      text = await webFile.text();
    } else {
      text = await new ExpoFile(asset.uri).text();
    }
    return { canceled: false, file: { name: asset.name ?? 'qrs-object.qrs', text } };
  } catch (e) {
    return { canceled: false, error: e instanceof Error ? e.message : 'Could not read the file.' };
  }
}
