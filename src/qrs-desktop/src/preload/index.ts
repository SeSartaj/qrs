/**
 * Preload script: exposes a typed, minimal API on `window.qrs` via contextBridge.
 * The renderer never touches Node or Electron APIs directly.
 */
import { contextBridge, ipcRenderer } from 'electron';
import {
  IPC,
  type AlgorithmId,
  type AttachmentGetInput,
  type AttachmentOpenInput,
  type AttachmentSaveInput,
  type AttachmentSubmitInput,
  type ContextReply,
  type ContextRequest,
  type CreateTcertInput,
  type ExportQrsInput,
  type ExportBundleInput,
  type GlobalConfig,
  type IssueInput,
  type KeyId,
  type QrsApi,
  type RevocationType,
  type SaveQrPngInput,
  type SdocId,
  type TcertId,
  type VerifyInput,
} from '../shared/types.js';

const api: QrsApi = {
  app: {
    getInfo: () => ipcRenderer.invoke(IPC.app.getInfo),
  },
  keys: {
    list: () => ipcRenderer.invoke(IPC.keys.list),
    generate: (algorithm: AlgorithmId) => ipcRenderer.invoke(IPC.keys.generate, algorithm),
  },
  certificates: {
    list: () => ipcRenderer.invoke(IPC.certificates.list),
    create: (input: CreateTcertInput) => ipcRenderer.invoke(IPC.certificates.create, input),
    get: (tcertId: TcertId) => ipcRenderer.invoke(IPC.certificates.get, tcertId),
    import: (bytesB64: string) => ipcRenderer.invoke(IPC.certificates.import, bytesB64),
    export: (tcertId: TcertId) => ipcRenderer.invoke(IPC.certificates.export, tcertId),
    remove: (tcertId: TcertId) => ipcRenderer.invoke(IPC.certificates.remove, tcertId),
  },
  documents: {
    list: () => ipcRenderer.invoke(IPC.documents.list),
    issue: (input: IssueInput) => ipcRenderer.invoke(IPC.documents.issue, input),
    get: (sdocId: SdocId) => ipcRenderer.invoke(IPC.documents.get, sdocId),
    import: (bytesB64: string) => ipcRenderer.invoke(IPC.documents.import, bytesB64),
    export: (sdocId: SdocId) => ipcRenderer.invoke(IPC.documents.export, sdocId),
    remove: (sdocId: SdocId) => ipcRenderer.invoke(IPC.documents.remove, sdocId),
  },
  trust: {
    state: () => ipcRenderer.invoke(IPC.trust.state),
    pin: (tcertId: TcertId) => ipcRenderer.invoke(IPC.trust.pin, tcertId),
    unpin: (tcertId: TcertId) => ipcRenderer.invoke(IPC.trust.unpin, tcertId),
    addCa: (tcertId: TcertId) => ipcRenderer.invoke(IPC.trust.addCa, tcertId),
    removeCa: (tcertId: TcertId) => ipcRenderer.invoke(IPC.trust.removeCa, tcertId),
    distrust: (tcertId: TcertId) => ipcRenderer.invoke(IPC.trust.distrust, tcertId),
    trustAgain: (tcertId: TcertId) => ipcRenderer.invoke(IPC.trust.trustAgain, tcertId),
    attest: (input: { caTcertId: TcertId; targetTcertId: TcertId; claims?: Record<string, unknown> }) =>
      ipcRenderer.invoke(IPC.trust.attest, input),
  },
  revocation: {
    state: () => ipcRenderer.invoke(IPC.revocation.state),
    revokeAttestation: (input: { caTcertId: TcertId; targetTcertId: TcertId; reason?: string }) =>
      ipcRenderer.invoke(IPC.revocation.revokeAttestation, input),
    revokeTcert: (input: { signerKeyId: KeyId; targetTcertId: TcertId; type: RevocationType; reason?: string }) =>
      ipcRenderer.invoke(IPC.revocation.revokeTcert, input),
    revokeKey: (input: { signerKeyId: KeyId; targetKeyId: KeyId; reason?: string }) =>
      ipcRenderer.invoke(IPC.revocation.revokeKey, input),
    blockSdoc: (input: { signerKeyId: KeyId; targetSdocId: SdocId; reason?: string }) =>
      ipcRenderer.invoke(IPC.revocation.blockSdoc, input),
    unblockSdoc: (input: { signerKeyId: KeyId; targetSdocId: SdocId; reason?: string }) =>
      ipcRenderer.invoke(IPC.revocation.unblockSdoc, input),
  },
  verification: {
    verify: (input: VerifyInput) => ipcRenderer.invoke(IPC.verification.verify, input),
  },
  objects: {
    decode: (bytesB64: string) => ipcRenderer.invoke(IPC.objects.decode, bytesB64),
    exportQrs: (input: ExportQrsInput) => ipcRenderer.invoke(IPC.objects.exportQrs, input),
    exportBundle: (input: ExportBundleInput) => ipcRenderer.invoke(IPC.objects.exportBundle, input),
    saveQrPng: (input: SaveQrPngInput) => ipcRenderer.invoke(IPC.objects.saveQrPng, input),
  },
  attachments: {
    submit: (input: AttachmentSubmitInput) => ipcRenderer.invoke(IPC.attachments.submit, input),
    sync: () => ipcRenderer.invoke(IPC.attachments.sync),
    syncTcert: (tcertId: TcertId) => ipcRenderer.invoke(IPC.attachments.syncTcert, tcertId),
    queue: () => ipcRenderer.invoke(IPC.attachments.queue),
    pending: () => ipcRenderer.invoke(IPC.attachments.pending),
    get: (input: AttachmentGetInput) => ipcRenderer.invoke(IPC.attachments.get, input),
    open: (input: AttachmentOpenInput) => ipcRenderer.invoke(IPC.attachments.open, input),
    save: (input: AttachmentSaveInput) => ipcRenderer.invoke(IPC.attachments.save, input),
  },
  endpoints: {
    list: (tcertId: TcertId) => ipcRenderer.invoke(IPC.endpoints.list, tcertId),
    mirrors: (tcertId: TcertId) => ipcRenderer.invoke(IPC.endpoints.mirrors, tcertId),
    add: (tcertId: TcertId, endpoint: string) => ipcRenderer.invoke(IPC.endpoints.add, tcertId, endpoint),
    remove: (tcertId: TcertId, endpoint: string) => ipcRenderer.invoke(IPC.endpoints.remove, tcertId, endpoint),
  },
  config: {
    get: () => ipcRenderer.invoke(IPC.config.get),
    set: (config: GlobalConfig) => ipcRenderer.invoke(IPC.config.set, config),
  },
  onContextRequest: (cb: (req: ContextRequest) => void) => {
    const listener = (_event: Electron.IpcRendererEvent, req: ContextRequest): void => cb(req);
    ipcRenderer.on(IPC.context.request, listener);
    return () => ipcRenderer.removeListener(IPC.context.request, listener);
  },
  replyContext: (reply: ContextReply) => ipcRenderer.send(IPC.context.reply, reply),
};

contextBridge.exposeInMainWorld('qrs', api);
