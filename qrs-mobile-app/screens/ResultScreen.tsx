/**
 * Verification result screen.
 *
 * Layout (top → bottom):
 *   CA name (verification tick)
 *   issuer name (verification tick if pinned)
 *   document name
 *   each field — label: value (a labeled validation icon only when invalid)
 *   validity summary + a scrollable details modal
 *   final verdict — VALID / INVALID / CANNOT BE VERIFIED
 *
 * "Cannot be verified" is shown when the issuing certificate cannot be found.
 */
import React, { useState } from 'react';
import { Dimensions, FlatList, ScrollView, StyleSheet, View, type NativeScrollEvent, type NativeSyntheticEvent } from 'react-native';
import { Appbar, Button, Divider, Icon, IconButton, Modal, Text, useTheme } from 'react-native-paper';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import type { RootStackParamList } from '../navigation/types';
import { VerifiedBadge } from '../components/VerifiedBadge';
import { AttachmentFieldView } from '../components/AttachmentFieldView';
import { verdictColor, VERIFIED_BLUE, SUCCESS, ERROR, WARNING } from '../lib/theme';
import { formatEpoch, formatFieldValue, getSettings, selectV2Option, type DateFormat } from '../lib/settings';
import type { CleanVerifyResult, CaView } from '../lib/verify';
import { verifySdoc } from '../lib/verify';
import { addHistory } from '../lib/history';

type Props = NativeStackScreenProps<RootStackParamList, 'Result'>;

const CHECK_LABELS: Record<string, string> = {
  cryptographic: 'Cryptographic signature',
  tcert: 'Issuing certificate',
  trust: 'Trust',
  revocation: 'Revocation',
  schema: 'Schema',
  context: 'Context',
};

function isOk(state: string): boolean {
  return state === 'valid' || state === 'satisfied';
}

/** One CA's swipeable "version" card: CA name at top + its trust/revocation state. */
function CaCard({ view, active }: { view: CaView; active: boolean }) {
  const theme = useTheme();
  const ok = view.state === 'valid';
  const color = ok ? SUCCESS : view.revoked ? ERROR : WARNING;
  const verdictLabel = ok ? 'TRUSTED BY THIS CA' : view.revoked ? 'REVOKED BY THIS CA' : 'NOT TRUSTED BY THIS CA';
  return (
    <View style={[styles.caCard, { borderColor: active ? theme.colors.primary : 'rgba(128,128,128,0.3)' }]}>
      <View style={styles.caCardHeader}>
        <Text variant="titleMedium" style={{ color: ok ? VERIFIED_BLUE : color, flex: 1 }}>
          {view.caName ?? view.caTcertId.slice(0, 12)}
        </Text>
        {ok ? <VerifiedBadge /> : <Icon source={view.revoked ? 'close-circle' : 'alert-circle'} size={20} color={color} />}
      </View>
      <View style={[styles.caVerdictBanner, { backgroundColor: color }]}>
        <Text variant="labelMedium" style={styles.white}>
          {verdictLabel}
        </Text>
      </View>
      {view.message ? (
        <Text variant="bodySmall" style={{ color: theme.colors.onSurfaceVariant, textAlign: 'center', marginTop: 8 }}>
          {view.message}
        </Text>
      ) : null}
    </View>
  );
}

/** Swipeable pager showing one CA "version" per page when 2+ CAs attest. */
function CaPager({ views, activeCa, onScroll }: { views: CaView[]; activeCa: number; onScroll: (e: NativeSyntheticEvent<NativeScrollEvent>) => void }) {
  const theme = useTheme();
  const width = Dimensions.get('window').width - 32; // content padding 16 each side
  const policyLabel = views.some((v) => v.revoked)
    ? 'Attested by multiple CAs with differing views — swipe to compare'
    : 'Attested by multiple CAs — swipe to view each';
  return (
    <View>
      <Text variant="labelSmall" style={[styles.swipeHint, { color: theme.colors.onSurfaceVariant }]}>
        {policyLabel}
      </Text>
      <FlatList
        data={views}
        keyExtractor={(v) => v.caTcertId}
        horizontal
        pagingEnabled
        showsHorizontalScrollIndicator={false}
        onMomentumScrollEnd={onScroll}
        renderItem={({ item, index }) => (
          <View style={{ width }}>
            <CaCard view={item} active={index === activeCa} />
          </View>
        )}
      />
      {/* Page dots */}
      <View style={styles.caDots}>
        {views.map((v, i) => (
          <View key={v.caTcertId} style={[styles.caDot, { backgroundColor: i === activeCa ? theme.colors.primary : 'rgba(128,128,128,0.4)' }]} />
        ))}
      </View>
    </View>
  );
}

/** One validity row: label : value, with a green tick when valid. */
function CheckRow({ label, state, message }: { label: string; state: string; message?: string }) {
  const ok = isOk(state);
  const warn = !ok && /cannot|missing|denied/.test(state);
  const color = ok ? SUCCESS : warn ? WARNING : ERROR;
  return (
    <View style={styles.checkBlock}>
      <View style={styles.checkRow}>
        <Text variant="bodyMedium" style={styles.checkLabel}>
          {label}
        </Text>
        <Text variant="bodyMedium" style={[styles.checkValue, { color }]}>
          {state}
        </Text>
        <Icon source={ok ? 'check-circle' : 'close-circle'} size={20} color={color} />
      </View>
      {message ? (
        <Text variant="bodySmall" style={[styles.checkMessage, { color }]}>
          {message}
        </Text>
      ) : null}
    </View>
  );
}

export function ResultScreen({ route, navigation }: Props) {
  const theme = useTheme();
  const [result, setResult] = useState<CleanVerifyResult | null>(route.params.result ?? null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [dateFormat, setDateFormat] = useState<DateFormat>('gregorian');
  const [activeCa, setActiveCa] = useState(0);

  React.useEffect(() => {
    if (!route.params.loading || !route.params.raw) return;
    let active = true;
    void verifySdoc(route.params.raw).then(async (verified) => {
      if ((await getSettings()).historyEnabled) {
        await addHistory({
          raw: route.params.raw as string,
          documentName: verified.documentName,
          issuerName: verified.issuerName,
          verdict: verified.verdict,
          ts: Date.now(),
        });
      }
      if (active) setResult(verified);
    }).catch(() => {
      if (active) navigation.goBack();
    });
    return () => { active = false; };
  }, [navigation, route.params.loading, route.params.raw]);

  // Load the user's date-format preference for displaying datetimeEpoch values.
  React.useEffect(() => {
    void (async () => {
      setDateFormat((await getSettings()).dateFormat);
    })();
  }, []);

  if (!result) {
    return (
      <View style={styles.root}>
        <Appbar.Header>
          <Appbar.BackAction onPress={() => navigation.goBack()} />
          <Appbar.Content title="Result" />
        </Appbar.Header>
        <View style={styles.loadingResult}>
          <Text variant="titleMedium">Verifying document…</Text>
          <Text variant="bodyMedium">Checking required attachments. This will stop if the internet is unavailable.</Text>
        </View>
      </View>
    );
  }

  const cannotVerify = result.verdict === 'cannotVerify';
  const color = verdictColor(result.verdict, theme.dark);
  const finalLabel = result.certificateMissing ? 'CANNOT BE VERIFIED' : result.verdict.toUpperCase();

  const fieldsWithValidity = result.values.filter((v) => v.state !== undefined);

  const multiCa = result.caViews.length >= 2;
  const onCaScroll = (e: NativeSyntheticEvent<NativeScrollEvent>): void => {
    const index = Math.round(e.nativeEvent.contentOffset.x / Math.max(1, e.nativeEvent.layoutMeasurement.width));
    setActiveCa(Math.max(0, Math.min(result.caViews.length - 1, index)));
  };

  return (
    <View style={styles.root}>
      <Appbar.Header>
        <Appbar.BackAction onPress={() => navigation.goBack()} />
        <Appbar.Content title="Result" />
      </Appbar.Header>

      <ScrollView contentContainerStyle={styles.content}>
        {/* Attesting CA(s): a swipeable pager when 2+ CAs attest, else a single CA name */}
        {multiCa ? (
          <CaPager views={result.caViews} activeCa={activeCa} onScroll={onCaScroll} />
        ) : result.issuerName || result.caName ? (
          <View style={styles.nameRow}>
            <Text variant="titleMedium" style={[styles.fullName, { color: VERIFIED_BLUE }]}>
              {result.issuerName ?? result.caName}
            </Text>
            {(result.caVerified || result.issuerPinned) ? <VerifiedBadge /> : null}
          </View>
        ) : null}

        {!result.issuerVerified && !result.certificateMissing && !result.caName && !multiCa ? (
          <Text variant="bodySmall" style={{ color: theme.colors.onSurfaceVariant, textAlign: 'center' }}>
            Not trusted — pin this certificate or add its CA to trust it.
          </Text>
        ) : null}

        {/* The TCert name; trust is represented by the CA badge above. */}
        <View style={styles.nameRow}>
          <Text variant="titleLarge" style={styles.fullName}>{result.documentName ?? 'Document'}</Text>
        </View>
        {result.issuedAt !== undefined ? <Text variant="bodySmall" style={styles.issuedAt}>{formatEpoch(result.issuedAt, dateFormat)}</Text> : null}

        <Divider style={{ marginVertical: 12 }} />

        {/* Certificate missing */}
        {result.certificateMissing ? (
          <View style={[styles.cannotBox, { backgroundColor: '#E37400' }]}>
            <Text variant="titleMedium" style={styles.white}>
              Cannot be verified
            </Text>
            <Text variant="bodyMedium" style={styles.white}>
              The issuing certificate was not found on this device. Import it (or the CA attestation bundle) to
              verify.
            </Text>
          </View>
        ) : null}

        {result.message ? (
          <Text variant="bodyMedium" style={{ color: theme.colors.onSurfaceVariant, marginBottom: 10 }}>
            {result.message}
          </Text>
        ) : null}

        {/* Fields (label : value, padded; only failed validation is shown beside the label) */}
        {result.values.length > 0 ? (
          <View style={styles.fields}>
            {result.values.map((v, i) => {
              const hasValidity = v.state !== undefined;
              const ok = hasValidity && isOk(v.state ?? '');
              const warn = hasValidity && /cannot|missing|denied/.test(v.state ?? '');
              return (
                <View key={`${v.label}-${i}`} style={styles.fieldBlock}>
                  <View style={styles.fieldRow}>
                    <View style={styles.fieldLabelRow}>
                      {hasValidity && !ok ? (
                        <Icon
                          source={warn ? 'alert-circle' : 'close-circle'}
                          size={18}
                          color={warn ? WARNING : ERROR}
                        />
                      ) : null}
                      <Text variant="bodyMedium" style={styles.fieldLabel}>
                        {v.label}
                      </Text>
                    </View>
                    {v.type === 'attachment' ? null : v.type === 'selectv2' ? (
                      <View style={styles.fieldValueRow}>
                        {(() => {
                          const index = typeof v.value === 'number' ? v.value : -1;
                          const raw = Array.isArray(v.options) ? v.options[index] : undefined;
                          const optColor = typeof raw === 'object' && raw !== null && 'color' in raw ? (raw as { color?: string }).color : undefined;
                          return optColor ? (
                            <View style={[styles.colorDot, { backgroundColor: optColor }]} />
                          ) : null;
                        })()}
                        <Text variant="bodyMedium" style={styles.fieldValue}>
                          {formatFieldValue(v.type, v.value, v.options, dateFormat)}
                        </Text>
                      </View>
                    ) : (
                      <Text variant="bodyMedium" style={styles.fieldValue}>
                        {formatFieldValue(v.type, v.value, v.options, dateFormat)}
                      </Text>
                    )}
                  </View>
                  {v.type === 'attachment' && (typeof v.value === 'string' || (typeof v.value === 'object' && v.value !== null)) && result.tcertId ? (
                    <AttachmentFieldView
                      reference={v.value as string | { hash: string; size?: number }}
                      contentType={v.contentType ?? 'application/octet-stream'}
                      tcertId={result.tcertId}
                    />
                  ) : null}
                  {hasValidity && !ok ? (
                    <Text variant="bodySmall" style={[styles.fieldNote, { color: warn ? WARNING : ERROR }]}>
                      {v.message ?? `Not verified (${v.state})`}
                    </Text>
                  ) : null}
                </View>
              );
            })}
          </View>
        ) : (
          <Text variant="bodyMedium" style={{ color: theme.colors.onSurfaceVariant }}>
            No stored values.
          </Text>
        )}

        <Divider style={{ marginVertical: 12 }} />

        {/* Detailed checks are kept out of the main summary. */}
        <View style={styles.validityHeader}>
          <Button mode="outlined" compact icon="clipboard-text-outline" onPress={() => setDetailsOpen(true)}>
            Details
          </Button>
        </View>

        {/* Final verdict */}
        <View style={[styles.final, { backgroundColor: color }]}>
          <Text variant="headlineMedium" style={styles.white}>
            {finalLabel}
          </Text>
        </View>

        <Button mode="outlined" icon="shield-check" style={styles.verifyAgain} onPress={() => navigation.goBack()}>
          Verify another document
        </Button>
      </ScrollView>

      {/* Validity details modal (scrollable) */}
      <Modal
        visible={detailsOpen}
        onDismiss={() => setDetailsOpen(false)}
        contentContainerStyle={styles.modalBox}
      >
        <View style={[styles.modalCard, { backgroundColor: theme.colors.surface }]}>
          <View style={styles.modalHeader}>
            <Text variant="titleMedium">Validity details</Text>
            <IconButton icon="close" onPress={() => setDetailsOpen(false)} />
          </View>
          <ScrollView style={styles.modalScroll}>
            <Text variant="bodySmall" style={styles.detailMetadata}>SDoc ID: {result.sdocId ?? '—'}</Text>
            <Text variant="bodySmall" style={styles.detailMetadata}>Size: {result.sizeBytes} bytes</Text>
            {result.warnings.length > 0 ? <Text variant="bodySmall" style={[styles.detailMetadata, { color: theme.colors.error }]}>{result.warnings.join('; ')}</Text> : null}
            <Text variant="titleSmall" style={styles.dialogSection}>
              Checks
            </Text>
            {result.breakdown.map((b) => (
              <CheckRow key={b.key} label={CHECK_LABELS[b.key] ?? b.key} state={b.state} />
            ))}

            {fieldsWithValidity.length > 0 ? (
              <>
                <Text variant="titleSmall" style={[styles.dialogSection, { marginTop: 12 }]}>
                  Fields
                </Text>
                {fieldsWithValidity.map((v, i) => (
                  <CheckRow
                    key={`f-${i}`}
                    label={v.label}
                    state={v.state ?? ''}
                    message={v.message}
                  />
                ))}
              </>
            ) : null}
          </ScrollView>
        </View>
      </Modal>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1 },
  loadingResult: { flex: 1, alignItems: 'center', justifyContent: 'center', gap: 10, padding: 24 },
  content: { padding: 16, paddingBottom: 40 },
  nameRow: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 6, marginBottom: 4 },
  caCard: { borderRadius: 14, borderWidth: 2, padding: 12, marginBottom: 8 },
  caCardHeader: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 6, marginBottom: 8 },
  caVerdictBanner: { borderRadius: 10, paddingVertical: 6, paddingHorizontal: 10, alignItems: 'center' },
  caDots: { flexDirection: 'row', justifyContent: 'center', gap: 6, marginBottom: 8 },
  caDot: { width: 8, height: 8, borderRadius: 4 },
  swipeHint: { textAlign: 'center', marginBottom: 6 },
  documentName: { fontWeight: '700', marginTop: 8, textAlign: 'center' },
  fullName: { flexShrink: 1, textAlign: 'center' },
  issuedAt: { textAlign: 'center', color: '#6A7280', marginBottom: 4 },
  cannotBox: { borderRadius: 12, padding: 14, marginBottom: 10 },
  white: { color: '#fff' },
  fields: { marginBottom: 4 },
  fieldBlock: { marginBottom: 2 },
  fieldRow: { flexDirection: 'row', alignItems: 'center', paddingVertical: 10, gap: 10 },
  fieldLabelRow: { flex: 1, flexDirection: 'row', alignItems: 'center', gap: 6 },
  fieldLabel: { color: '#6A7280', flex: 1, fontSize: 14, lineHeight: 20 },
  fieldValue: { fontWeight: '600', flex: 2, fontSize: 14, lineHeight: 20 },
  fieldValueRow: { flexDirection: 'row', alignItems: 'center', flex: 2, gap: 6 },
  colorDot: { width: 12, height: 12, borderRadius: 6 },
  fieldNote: { marginBottom: 6, marginTop: -6, marginLeft: 2 },
  validityHeader: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  final: { borderRadius: 16, padding: 20, alignItems: 'center', marginTop: 14 },
  verifyAgain: { marginTop: 14 },
  // Validity details modal
  modalBox: { padding: 20 },
  modalCard: { borderRadius: 16, maxHeight: '85%', overflow: 'hidden', elevation: 4 },
  modalHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 16,
    paddingTop: 8,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: 'rgba(128,128,128,0.25)',
  },
  modalScroll: { paddingHorizontal: 16, paddingTop: 8, paddingBottom: 16 },
  detailMetadata: { color: '#6A7280', marginBottom: 6 },
  dialogSection: { marginBottom: 4, opacity: 0.7 },
  checkBlock: { marginBottom: 8 },
  checkRow: { flexDirection: 'row', alignItems: 'center', gap: 8, paddingVertical: 2 },
  checkLabel: { flex: 1, fontSize: 14 },
  checkValue: { fontWeight: '600', fontSize: 13, textTransform: 'capitalize' },
  checkMessage: { marginTop: 2, marginLeft: 2, fontSize: 12 },
});
