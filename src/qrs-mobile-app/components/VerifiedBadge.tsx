/**
 * The "verified" badge — a blue check mark (Twitter/X style) shown next to an
 * issuer or CA name that is trusted.
 */
import React from 'react';
import { StyleSheet, View } from 'react-native';
import { Icon } from 'react-native-paper';
import { VERIFIED_BLUE } from '../lib/theme';

interface Props {
  /** Render only the badge, or badge + label text. */
  withLabel?: boolean;
  size?: number;
  color?: string;
}

export function VerifiedBadge({ withLabel = false, size = 16, color = VERIFIED_BLUE }: Props) {
  if (withLabel) {
    return (
      <View style={styles.row}>
        <BadgeCheck size={size} color={color} />
      </View>
    );
  }
  return <BadgeCheck size={size} color={color} />;
}

function BadgeCheck({ size, color }: { size: number; color: string }) {
  return (
    <View style={[styles.badge, { width: size + 4, height: size + 4, backgroundColor: color }]}>
      <Icon source="check-bold" size={size - 2} color="#fff" />
    </View>
  );
}

const styles = StyleSheet.create({
  row: { flexDirection: 'row', alignItems: 'center' },
  badge: {
    borderRadius: 999,
    alignItems: 'center',
    justifyContent: 'center',
    marginLeft: 4,
  },
});
