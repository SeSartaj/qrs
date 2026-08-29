import type { CleanVerifyResult } from '../lib/verify';
import type { ProcessOutcome } from '../lib/process';

export type RootStackParamList = {
  Tabs: undefined;
  Result: { result?: CleanVerifyResult; loading?: boolean; raw?: string };
  Processed: { outcome: ProcessOutcome };
  ChangePassword: undefined;
  Data: undefined;
  Preferences: undefined;
  TrustPolicy: undefined;
  TcertDetail: { tcertId: string };
};

export type TabParamList = {
  Verify: undefined;
  Trust: undefined;
  Scan: undefined;
  History: undefined;
  Settings: undefined;
};
