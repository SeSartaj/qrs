import React, { useState } from 'react';
import { TextInput, type TextInputProps } from 'react-native-paper';

/** Paper password field with an accessible show/hide password control. */
export function PasswordInput({ label = 'Password', ...props }: TextInputProps) {
  const [shown, setShown] = useState(false);

  return (
    <TextInput
      {...props}
      label={label}
      secureTextEntry={!shown}
      right={(
        <TextInput.Icon
          icon={shown ? 'eye-off' : 'eye'}
          onPress={() => setShown((value) => !value)}
          accessibilityLabel={shown ? 'Hide password' : 'Show password'}
          forceTextInputFocus={false}
        />
      )}
    />
  );
}
