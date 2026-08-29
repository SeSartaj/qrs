/**
 * Host dialog that renders when verification needs a secret (passcode). Mounted
 * once at the app root.
 */
import React, { useState, useSyncExternalStore } from 'react';
import { Dialog, Portal, Text, TextInput, Button } from 'react-native-paper';
import { getPendingSecret, settleSecret, subscribe } from '../lib/secretPrompt';

export function SecretPromptHost() {
  const pending = useSyncExternalStore(subscribe, getPendingSecret, getPendingSecret);
  const [value, setValue] = useState('');

  React.useEffect(() => {
    if (pending) setValue('');
  }, [pending]);

  const visible = !!pending;
  return (
    <Portal>
      <Dialog visible={visible} onDismiss={() => settleSecret(null)}>
        <Dialog.Icon icon="key-variant" />
        <Dialog.Title style={{ textAlign: 'center' }}>Enter {pending?.field.label ?? 'passcode'}</Dialog.Title>
        <Dialog.Content>
          <Text variant="bodyMedium" style={{ textAlign: 'center', marginBottom: 8 }}>
            This document is protected. Enter the value for “{pending?.field.label ?? 'secret'}” to verify it.
          </Text>
          <TextInput
            mode="outlined"
            autoFocus
            value={value}
            onChangeText={setValue}
            onSubmitEditing={() => settleSecret(value.length ? value : null)}
          />
        </Dialog.Content>
        <Dialog.Actions>
          <Button onPress={() => settleSecret(null)}>Cancel</Button>
          <Button mode="contained" disabled={!value} onPress={() => settleSecret(value)}>
            Verify
          </Button>
        </Dialog.Actions>
      </Dialog>
    </Portal>
  );
}
