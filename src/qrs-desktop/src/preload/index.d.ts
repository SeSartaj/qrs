import type { QrsApi } from '../shared/types';

declare global {
  interface Window {
    qrs: QrsApi;
  }
}

export {};
