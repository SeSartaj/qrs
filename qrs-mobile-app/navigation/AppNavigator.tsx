/**
 * Navigation: a root native stack (tabs + full-screen result/processed/settings
 * pages) and a custom bottom tab bar. The Scan tab is the default screen and is
 * rendered as a raised, primary-colored circular button centered in the bar:
 *
 *   Verify | Trust | [Scan] | History | Settings
 *   (2 tabs each side of the raised Scan button — balanced)
 */
import React from 'react';
import { Pressable, StyleSheet, View } from 'react-native';
import { NavigationContainer, DefaultTheme, DarkTheme, createNavigationContainerRef } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import { createBottomTabNavigator, type BottomTabBarProps } from '@react-navigation/bottom-tabs';
import { useColorScheme } from 'react-native';
import { Icon, Text, useTheme, PaperProvider } from 'react-native-paper';
import { BottomSheetModalProvider } from '@gorhom/bottom-sheet';

import { VerifyScreen } from '../screens/VerifyScreen';
import { ScanScreen } from '../screens/ScanScreen';
import { TrustScreen } from '../screens/TrustScreen';
import { HistoryScreen } from '../screens/HistoryScreen';
import { SettingsScreen } from '../screens/SettingsScreen';
import { ResultScreen } from '../screens/ResultScreen';
import { ProcessedScreen } from '../screens/ProcessedScreen';
import { ChangePasswordScreen } from '../screens/ChangePasswordScreen';
import { DataScreen } from '../screens/DataScreen';
import { PreferencesScreen } from '../screens/PreferencesScreen';
import { TrustPolicyScreen } from '../screens/TrustPolicyScreen';
import { TcertDetailScreen } from '../screens/TcertDetailScreen';
import { SecretPromptHost } from '../components/SecretPromptHost';
import { lightTheme, darkTheme } from '../lib/theme';
import type { RootStackParamList, TabParamList } from './types';

/** Module-level navigation ref so deep-link handlers can navigate from anywhere. */
export const navigationRef = createNavigationContainerRef<RootStackParamList>();

const Stack = createNativeStackNavigator<RootStackParamList>();
const Tabs = createBottomTabNavigator<TabParamList>();

type TabIconName = 'shield-check' | 'qrcode-scan' | 'shield-account' | 'history' | 'cog';

const BAR_HEIGHT = 60;
const SCAN_SIZE = 56;

function iconOf(name: string): TabIconName {
  switch (name) {
    case 'Verify':
      return 'shield-check';
    case 'Scan':
      return 'qrcode-scan';
    case 'Trust':
      return 'shield-account';
    case 'History':
      return 'history';
    default:
      return 'cog';
  }
}

/**
 * Bottom tab bar: Verify | Trust | Scan | History | Settings. Scan is a raised,
 * primary-colored circular button centered in the bar (2 tabs on each side),
 * floating slightly above the bar like a primary action / FAB.
 */
function CustomTabBar({ state, navigation }: BottomTabBarProps) {
  const theme = useTheme();

  const go = (name: string): void => {
    const route = state.routes.find((r) => r.name === name);
    if (!route) return;
    const event = navigation.emit({ type: 'tabPress', target: route.key, canPreventDefault: true });
    if (!event.defaultPrevented) navigation.navigate(route.name, route.params);
  };

  const renderTab = (name: string, index: number): React.ReactElement => {
    const focused = state.index === index;
    const color = focused ? theme.colors.primary : theme.colors.onSurfaceVariant;
    return (
      <Pressable
        key={name}
        style={styles.tabItem}
        onPress={() => go(name)}
        accessibilityRole="button"
        accessibilityState={{ selected: focused }}
      >
        <Icon source={iconOf(name)} size={22} color={color} />
        <Text style={[styles.tabLabel, { color }]}>{name}</Text>
      </Pressable>
    );
  };

  return (
    <View style={[styles.wrap, { backgroundColor: theme.colors.surface }]}>
      <View style={[styles.bar, { borderTopColor: theme.colors.outlineVariant }]}>
        {renderTab('Verify', 0)}
        {renderTab('Trust', 1)}
        <View style={styles.centerSlot} />
        {renderTab('History', 3)}
        {renderTab('Settings', 4)}
      </View>
      <Pressable
        style={({ pressed }) => [
          styles.scanBtn,
          { backgroundColor: theme.colors.primary, bottom: BAR_HEIGHT - SCAN_SIZE / 2 },
          pressed && styles.scanPressed,
        ]}
        onPress={() => go('Scan')}
        accessibilityRole="button"
        accessibilityLabel="Scan"
        accessibilityState={{ selected: state.index === 2 }}
      >
        <Icon source="qrcode-scan" size={30} color="#fff" />
      </Pressable>
    </View>
  );
}

function TabNavigator() {
  return (
    <Tabs.Navigator
      initialRouteName="Scan"
      screenOptions={{ headerShown: false }}
      tabBar={(props) => <CustomTabBar {...props} />}
    >
      <Tabs.Screen name="Verify" component={VerifyScreen} />
      <Tabs.Screen name="Trust" component={TrustScreen} />
      <Tabs.Screen name="Scan" component={ScanScreen} />
      <Tabs.Screen name="History" component={HistoryScreen} />
      <Tabs.Screen name="Settings" component={SettingsScreen} />
    </Tabs.Navigator>
  );
}

export function AppNavigator() {
  const scheme = useColorScheme();
  const isDark = scheme === 'dark';
  const navTheme = isDark ? DarkTheme : DefaultTheme;

  return (
    <PaperProvider theme={isDark ? darkTheme : lightTheme}>
      <BottomSheetModalProvider>
      <NavigationContainer ref={navigationRef} theme={navTheme}>
        <Stack.Navigator screenOptions={{ headerShown: false }}>
          <Stack.Screen name="Tabs" component={TabNavigator} />
          <Stack.Screen name="Result" component={ResultScreen} options={{ animation: 'slide_from_right' }} />
          <Stack.Screen name="Processed" component={ProcessedScreen} options={{ animation: 'slide_from_right' }} />
          <Stack.Screen name="ChangePassword" component={ChangePasswordScreen} options={{ animation: 'slide_from_right' }} />
          <Stack.Screen name="Data" component={DataScreen} options={{ animation: 'slide_from_right' }} />
          <Stack.Screen name="Preferences" component={PreferencesScreen} options={{ animation: 'slide_from_right' }} />
          <Stack.Screen name="TrustPolicy" component={TrustPolicyScreen} options={{ animation: 'slide_from_right' }} />
          <Stack.Screen name="TcertDetail" component={TcertDetailScreen} options={{ animation: 'slide_from_right' }} />
        </Stack.Navigator>
        <SecretPromptHost />
      </NavigationContainer>
      </BottomSheetModalProvider>
    </PaperProvider>
  );
}

const styles = StyleSheet.create({
  wrap: {},
  bar: { flexDirection: 'row', height: BAR_HEIGHT, borderTopWidth: StyleSheet.hairlineWidth },
  tabItem: { flex: 1, alignItems: 'center', justifyContent: 'center', gap: 2 },
  centerSlot: { flex: 1 },
  tabLabel: { fontSize: 11, marginTop: 2 },
  scanBtn: {
    position: 'absolute',
    left: '50%',
    marginLeft: -SCAN_SIZE / 2,
    width: SCAN_SIZE,
    height: SCAN_SIZE,
    borderRadius: SCAN_SIZE / 2,
    alignItems: 'center',
    justifyContent: 'center',
    elevation: 6,
    shadowColor: '#000',
    shadowOpacity: 0.28,
    shadowRadius: 6,
    shadowOffset: { width: 0, height: 3 },
    borderWidth: 3,
    borderColor: '#ffffff',
  },
  scanPressed: { transform: [{ scale: 0.94 }] },
});
