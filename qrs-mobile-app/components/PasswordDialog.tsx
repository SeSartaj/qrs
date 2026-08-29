/** Password dialog used to gate trust actions. */
import React, { useEffect, useState } from 'react';
import { StyleSheet } from 'react-native';
import { Button, Dialog, Portal, Text } from 'react-native-paper';
import { PasswordInput } from './PasswordInput';

interface Props {
  visible: boolean;
  title: string;
  message?: string;
  onCancel: () => void;
  onConfirm: (password: string) => Promise<boolean>;
}

export function PasswordDialog({ visible, title, message, onCancel, onConfirm }: Props) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (visible) {
      setPassword('');
      setError(null);
      setBusy(false);
    }
  }, [visible]);

  const submit = async (): Promise<void> => {
    if (!password || busy) return;
    setBusy(true);
    setError(null);
    const ok = await onConfirm(password);
    setBusy(false);
    if (!ok) {
      setPassword('');
      setError('Incorrect password.');
    }
  };

  return (
    <Portal>
      <Dialog visible={visible} onDismiss={onCancel}>
        <Dialog.Icon icon="lock" />
        <Dialog.Title style={styles.center}>{title}</Dialog.Title>
        {message ? <Dialog.Content><Text style={styles.center}>{message}</Text></Dialog.Content> : null}
        <Dialog.Content>
          <PasswordInput
            mode="outlined"
            label="Admin password"
            autoFocus
            value={password}
            onChangeText={setPassword}
            onSubmitEditing={() => void submit()}
            error={!!error}
          />
          {error ? <Text style={styles.error}>{error}</Text> : null}
        </Dialog.Content>
        <Dialog.Actions>
          <Button onPress={onCancel} disabled={busy}>Cancel</Button>
          <Button mode="contained" onPress={() => void submit()} loading={busy} disabled={!password || busy}>
            Confirm
          </Button>
        </Dialog.Actions>
      </Dialog>
    </Portal>
  );
}

const styles = StyleSheet.create({ center: { textAlign: 'center' }, error: { color: '#D93025', marginTop: 6 } });
