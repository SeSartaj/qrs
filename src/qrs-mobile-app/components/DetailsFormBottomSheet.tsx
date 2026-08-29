import React, {
  forwardRef,
  useCallback,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
} from 'react';
import { Keyboard, StyleSheet } from 'react-native';
import {
  BottomSheetBackdrop,
  BottomSheetModal,
  BottomSheetScrollView,
  BottomSheetTextInput,
  type BottomSheetBackdropProps,
} from '@gorhom/bottom-sheet';
import { Button, Text, useTheme } from 'react-native-paper';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

export interface DetailsFormValues {
  title: string;
  details: string;
}

export interface DetailsFormBottomSheetHandle {
  present: () => void;
  dismiss: () => void;
}

interface Props {
  heading?: string;
  onSubmit: (values: DetailsFormValues) => void | Promise<void>;
}

/** A reusable, imperative modal sheet for short forms. */
export const DetailsFormBottomSheet = forwardRef<DetailsFormBottomSheetHandle, Props>(
  function DetailsFormBottomSheet({ heading = 'Add details', onSubmit }, ref) {
    const theme = useTheme();
    const insets = useSafeAreaInsets();
    const modalRef = useRef<BottomSheetModal>(null);
    const detailsRef = useRef<React.ElementRef<typeof BottomSheetTextInput>>(null);
    const [title, setTitle] = useState('');
    const [details, setDetails] = useState('');
    const [submitting, setSubmitting] = useState(false);
    const [submitError, setSubmitError] = useState<string | null>(null);

    const reset = useCallback(() => {
      setTitle('');
      setDetails('');
      setSubmitting(false);
      setSubmitError(null);
    }, []);

    const present = useCallback(() => {
      reset();
      modalRef.current?.present();
    }, [reset]);
    const dismiss = useCallback(() => {
      Keyboard.dismiss();
      modalRef.current?.dismiss();
    }, []);
    useImperativeHandle(ref, () => ({ present, dismiss }), [dismiss, present]);

    const submit = useCallback(async () => {
      const trimmedTitle = title.trim();
      if (!trimmedTitle || submitting) return;
      setSubmitting(true);
      setSubmitError(null);
      try {
        await onSubmit({ title: trimmedTitle, details: details.trim() });
        dismiss();
      } catch (error) {
        setSubmitError(error instanceof Error ? error.message : 'Could not submit. Try again.');
      } finally {
        setSubmitting(false);
      }
    }, [details, dismiss, onSubmit, submitting, title]);

    const renderBackdrop = useCallback(
      (props: BottomSheetBackdropProps) => (
        <BottomSheetBackdrop
          {...props}
          appearsOnIndex={0}
          disappearsOnIndex={-1}
          pressBehavior="close"
          accessibilityLabel="Close form"
        />
      ),
      [],
    );

    const backgroundStyle = useMemo(
      () => ({ backgroundColor: theme.colors.surface }),
      [theme.colors.surface],
    );
    const handleIndicatorStyle = useMemo(
      () => ({ backgroundColor: theme.colors.onSurfaceVariant }),
      [theme.colors.onSurfaceVariant],
    );
    const snapPoints = useMemo(() => ['70%', '90%'], []);

    return (
      <BottomSheetModal
        ref={modalRef}
        snapPoints={snapPoints}
        enableDynamicSizing={false}
        enablePanDownToClose
        enableBlurKeyboardOnGesture
        keyboardBehavior="interactive"
        keyboardBlurBehavior="restore"
        android_keyboardInputMode="adjustResize"
        backdropComponent={renderBackdrop}
        onDismiss={reset}
        backgroundStyle={backgroundStyle}
        handleIndicatorStyle={handleIndicatorStyle}
        accessible
        accessibilityLabel={heading}
      >
        <BottomSheetScrollView
          contentContainerStyle={[
            styles.content,
            { paddingBottom: Math.max(24, insets.bottom + 16) },
          ]}
          keyboardDismissMode="interactive"
          keyboardShouldPersistTaps="handled"
        >
          <Text variant="titleLarge" accessibilityRole="header">
            {heading}
          </Text>
          <BottomSheetTextInput
            style={[
              styles.input,
              { color: theme.colors.onSurface, borderColor: theme.colors.outline },
            ]}
            value={title}
            onChangeText={setTitle}
            placeholder="Title"
            placeholderTextColor={theme.colors.onSurfaceVariant}
            accessibilityLabel="Title"
            autoFocus
            returnKeyType="next"
            blurOnSubmit={false}
            onSubmitEditing={() => detailsRef.current?.focus()}
          />
          <BottomSheetTextInput
            ref={detailsRef}
            style={[
              styles.input,
              styles.multilineInput,
              { color: theme.colors.onSurface, borderColor: theme.colors.outline },
            ]}
            value={details}
            onChangeText={setDetails}
            placeholder="Details"
            placeholderTextColor={theme.colors.onSurfaceVariant}
            accessibilityLabel="Details"
            multiline
            textAlignVertical="top"
            returnKeyType="default"
          />
          {submitError ? (
            <Text accessibilityRole="alert" style={{ color: theme.colors.error }}>
              {submitError}
            </Text>
          ) : null}
          <Button
            mode="contained"
            onPress={() => void submit()}
            disabled={!title.trim() || submitting}
            loading={submitting}
            contentStyle={styles.buttonContent}
            accessibilityLabel="Submit details"
          >
            Submit
          </Button>
          <Button onPress={dismiss} disabled={submitting} contentStyle={styles.buttonContent}>
            Cancel
          </Button>
        </BottomSheetScrollView>
      </BottomSheetModal>
    );
  },
);

const styles = StyleSheet.create({
  content: { paddingHorizontal: 24, paddingTop: 8, gap: 12 },
  input: { borderWidth: 1, borderRadius: 8, paddingHorizontal: 14, minHeight: 52, fontSize: 16 },
  multilineInput: { minHeight: 112, paddingTop: 12 },
  buttonContent: { minHeight: 48 },
});
