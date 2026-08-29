/**
 * CLI command implementations. This is a thin demo layer over the core: it wires
 * file-backed stores + the terminal context provider and exposes the protocol
 * operations as commands. The core itself never knows about the CLI.
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { adaptProvider, type IContextProvider } from '../context/context.js';
import { TerminalContextProvider } from '../context/terminalContext.js';
import type { FieldSchema } from '../fields/types.js';
import { fromBase64Url, toBase64Url, toHex } from '../id.js';
import { createQrs, type QrsRuntime } from '../runtime.js';
import { parseSignedObject, splitTcertId, tcertIdOf } from '../signedObject/signedObject.js';
import { createFileStores } from '../storage/fileStores.js';
import type { AlgorithmId, GeoPoint, RevocationType } from '../types.js';
import type { VerificationResult } from '../services/verificationService.js';
import { ask, askAlgorithm, askFieldValue, askRevocationType, buildSchemaInteractively } from './prompts.js';

const VERSION = '0.1.0';

interface ParsedArgs {
  positionals: string[];
  flags: Record<string, string | true>;
}

function parseArgs(argv: string[]): ParsedArgs {
  const positionals: string[] = [];
  const flags: Record<string, string | true> = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? '';
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=');
      if (eq !== -1) {
        flags[arg.slice(2, eq)] = arg.slice(eq + 1);
      } else {
        const next = argv[i + 1];
        if (next !== undefined && !next.startsWith('--')) {
          flags[arg.slice(2)] = next;
          i++;
        } else {
          flags[arg.slice(2)] = true;
        }
      }
    } else {
      positionals.push(arg);
    }
  }
  return { positionals, flags };
}

function flag(flags: ParsedArgs['flags'], name: string, def = ''): string {
  const v = flags[name];
  return v === undefined || v === true ? def : v;
}

function dataDirOf(flags: ParsedArgs['flags']): string {
  return flag(flags, 'data-dir') || process.env.QRS_DATA_DIR || './.qrs-data';
}

function parseLocation(value: string): GeoPoint | null {
  const parts = value.split(',').map((s) => parseFloat(s.trim()));
  const lat = parts[0];
  const lon = parts[1];
  if (lat === undefined || lon === undefined || !Number.isFinite(lat) || !Number.isFinite(lon)) return null;
  return { lat, lon };
}

/**
 * Context provider for a single CLI invocation: terminal prompts by default, with
 * scripted overrides from `--secret k=v`, `--location lat,lon` and `--time <epoch>`.
 */
function buildContextProvider(flags: ParsedArgs['flags']): IContextProvider {
  const terminal = new TerminalContextProvider();
  const secrets: Record<string, string> = {};
  for (const pair of flag(flags, 'secret').split(',')) {
    const eq = pair.indexOf('=');
    if (eq > 0) secrets[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
  }
  const location = flag(flags, 'location') ? parseLocation(flag(flags, 'location')) : undefined;
  const time = flag(flags, 'time') ? Number(flag(flags, 'time')) : undefined;

  return {
    getCurrentTime: () => (time !== undefined ? time : terminal.getCurrentTime()),
    requestLocation: async (field) => (location ? location : terminal.requestLocation(field)),
    requestSecret: async (field) => {
      const v = secrets[field.name];
      if (v !== undefined) return v === '' ? null : v;
      return terminal.requestSecret(field);
    },
    requestObject: (id) => terminal.requestObject(id),
    buildContext() {
      return adaptProvider(this);
    },
  };
}

function buildRuntime(dir: string, flags: ParsedArgs['flags']): QrsRuntime {
  const stores = createFileStores(dir);
  return createQrs({ ...stores, contextProvider: buildContextProvider(flags) });
}

function readBytes(input: string): Uint8Array {
  if (existsSync(input)) return new Uint8Array(readFileSync(input));
  try {
    return fromBase64Url(input);
  } catch {
    return new Uint8Array(Buffer.from(input, 'base64'));
  }
}

function writeSdocFile(dir: string, sdocId: string, bytes: Uint8Array): void {
  writeFileSync(join(dir, `${sdocId}.sdoc.bin`), bytes);
}

async function resolveSdocSignerKey(runtime: QrsRuntime, sdocId: string): Promise<string | null> {
  const bytes = await runtime.deps.documentStore.get(sdocId);
  if (!bytes) return null;
  const parsed = parseSignedObject(bytes);
  return parsed.signerKeyId;
}

function printVerificationResult(result: VerificationResult): void {
  console.log('--- verification result ---');
  console.log(`overall: ${result.overall}`);
  if (result.message) console.log(`message: ${result.message}`);
  if (result.sdocId) console.log(`sdocId: ${result.sdocId}`);
  if (result.tcertId) console.log(`tcertId: ${result.tcertId}`);
  console.log(`cryptographic: ${result.cryptographic}`);
  console.log(`tcert: ${result.tcert}`);
  console.log(`trust: ${result.trust}`);
  console.log(`revocation: ${result.revocation}`);
  console.log(`schema: ${result.schema}`);
  for (const field of result.fields) {
    console.log(`  ${field.name}: ${field.state}${field.message ? ` (${field.message})` : ''}`);
  }
  for (const warning of result.warnings) console.log(`  warning: ${warning}`);
}

async function dispatch(runtime: QrsRuntime, command: string, args: ParsedArgs): Promise<void> {
  const { positionals, flags } = args;

  switch (command) {
    case 'generate-key': {
      const algorithm = (flag(flags, 'algorithm') as AlgorithmId) || (await askAlgorithm());
      const keyId = await runtime.certificates.generateKeyPair(algorithm);
      console.log(`keyId: ${keyId}`);
      console.log(`algorithm: ${algorithm}`);
      return;
    }

    case 'create-tcert': {
      const name = flag(flags, 'name') || (await ask('Name: '));
      const algorithm = (flag(flags, 'algorithm') as AlgorithmId) || (await askAlgorithm());
      const keyId = flag(flags, 'key-id') || undefined;
      const validAfter = flag(flags, 'valid-after') ? Number(flag(flags, 'valid-after')) : undefined;
      const validBefore = flag(flags, 'valid-before') ? Number(flag(flags, 'valid-before')) : undefined;
      const onlineEndpoint = flag(flags, 'endpoint') || undefined;
      const fieldsRaw = flag(flags, 'fields-json');
      let fields: FieldSchema[];
      if (fieldsRaw) {
        const parsed: unknown = JSON.parse(fieldsRaw);
        if (!Array.isArray(parsed)) throw new Error('--fields-json must be a JSON array of field schemas');
        fields = parsed as FieldSchema[];
      } else {
        fields = await buildSchemaInteractively();
      }
      const result = await runtime.certificates.createTcert({
        algorithm,
        name,
        fields,
        keyId,
        validAfter,
        validBefore,
        onlineEndpoint,
      });
      console.log(`tcertId: ${result.tcertId}`);
      console.log(`keyId: ${result.keyId}`);
      console.log(`base64: ${toBase64Url(result.bytes)}`);
      return;
    }

    case 'issue': {
      const tcertId = flag(flags, 'tcert') || (await ask('TCert id: '));
      const issuedAt = flag(flags, 'issued-at') ? Number(flag(flags, 'issued-at')) : undefined;
      const { parsed } = await runtime.certificates.getTcert(tcertId);
      const schemaFields = parsed.data.schema as unknown as FieldSchema[];
      const valuesRaw = flag(flags, 'values-json');
      let values: Record<string, unknown>;
      if (valuesRaw) {
        const parsedValues: unknown = JSON.parse(valuesRaw);
        if (typeof parsedValues !== 'object' || parsedValues === null || Array.isArray(parsedValues)) {
          throw new Error('--values-json must be a JSON object of field values');
        }
        values = parsedValues as Record<string, unknown>;
      } else {
        values = {};
        for (const field of schemaFields) {
          const value = await askFieldValue(field);
          if (value !== undefined) values[field.name] = value;
        }
      }
      const result = await runtime.signing.issueSdoc({ tcertId, values, issuedAt });
      const dir = dataDirOf(flags);
      writeSdocFile(dir, result.sdocId, result.bytes);
      console.log(`sdocId: ${result.sdocId}`);
      console.log(`issuedAt: ${result.issuedAt}`);
      console.log(`saved: ${join(dir, `${result.sdocId}.sdoc.bin`)}`);
      console.log(`base64: ${toBase64Url(result.bytes)}`);
      return;
    }

    case 'verify': {
      const input = positionals[0];
      if (!input) throw new Error('usage: qrs verify <base64-or-file>');
      const bytes = readBytes(input);
      const currentTime = flag(flags, 'time') ? Number(flag(flags, 'time')) : undefined;
      const result = await runtime.verification.verify(
        bytes,
        currentTime !== undefined ? { currentTime } : {}
      );
      printVerificationResult(result);
      return;
    }

    case 'pin': {
      const tcertId = flag(flags, 'tcert') || positionals[0];
      if (!tcertId) throw new Error('pin requires --tcert <id>');
      await runtime.trust.pin(tcertId);
      console.log(`pinned: ${tcertId}`);
      return;
    }
    case 'unpin': {
      const tcertId = flag(flags, 'tcert') || positionals[0];
      if (!tcertId) throw new Error('unpin requires --tcert <id>');
      await runtime.trust.unpin(tcertId);
      console.log(`unpinned: ${tcertId}`);
      return;
    }
    case 'add-ca': {
      const tcertId = flag(flags, 'tcert') || positionals[0];
      if (!tcertId) throw new Error('add-ca requires --tcert <id>');
      await runtime.trust.addCa(tcertId);
      console.log(`CA role granted: ${tcertId}`);
      return;
    }
    case 'remove-ca': {
      const tcertId = flag(flags, 'tcert') || positionals[0];
      if (!tcertId) throw new Error('remove-ca requires --tcert <id>');
      await runtime.trust.removeCa(tcertId);
      console.log(`CA role removed: ${tcertId}`);
      return;
    }
    case 'distrust': {
      const tcertId = flag(flags, 'tcert') || positionals[0];
      if (!tcertId) throw new Error('distrust requires --tcert <id>');
      await runtime.trust.distrust(tcertId);
      console.log(`distrusted: ${tcertId}`);
      return;
    }
    case 'trust': {
      const tcertId = flag(flags, 'tcert') || positionals[0];
      if (!tcertId) throw new Error('trust requires --tcert <id>');
      await runtime.trust.trustAgain(tcertId);
      console.log(`distrust removed: ${tcertId}`);
      return;
    }

    case 'attest': {
      const caTcertId = flag(flags, 'ca');
      const targetTcertId = flag(flags, 'target');
      if (!caTcertId || !targetTcertId) throw new Error('attest requires --ca <caTcertId> --target <tcertId>');
      const claims = flag(flags, 'name') ? { name: flag(flags, 'name') } : undefined;
      const result = await runtime.trust.attest({ caTcertId, targetTcertId, claims });
      console.log(`attestation: ${result.statementId}`);
      console.log(`base64: ${toBase64Url(result.bytes)}`);
      return;
    }

    case 'add-tcert': {
      const caTcertId = flag(flags, 'ca');
      const targetTcertId = flag(flags, 'target');
      if (!caTcertId || !targetTcertId) throw new Error('add-tcert requires --ca <caTcertId> --target <tcertId>');
      const claims = flag(flags, 'name') ? { name: flag(flags, 'name') } : undefined;
      const tcertB64 = flag(flags, 'tcert-bytes');
      const result = await runtime.trust.addTcert({
        caTcertId,
        targetTcertId,
        claims,
        tcertBytes: tcertB64 ? readBytes(tcertB64) : undefined,
      });
      console.log(`add-tcert statement: ${result.statementId}`);
      console.log(`base64: ${toBase64Url(result.bytes)}`);
      return;
    }

    case 'revoke-tcert': {
      const targetTcertId = flag(flags, 'target') || positionals[0];
      if (!targetTcertId) throw new Error('revoke-tcert requires --target <tcertId>');
      const defaultSigner = splitTcertId(targetTcertId).keyId;
      const signerKeyId = flag(flags, 'signer') || defaultSigner;
      const type = (flag(flags, 'type') as RevocationType) || (await askRevocationType());
      const reason = flag(flags, 'reason') || undefined;
      const result = await runtime.revocation.revokeTcert({ signerKeyId, targetTcertId, type, reason });
      console.log(`revocation statement: ${result.statementId}`);
      console.log(`type: ${type}`);
      return;
    }

    case 'revoke-key': {
      const targetKeyId = flag(flags, 'target') || positionals[0];
      if (!targetKeyId) throw new Error('revoke-key requires --target <keyId>');
      const signerKeyId = flag(flags, 'signer') || targetKeyId;
      const reason = flag(flags, 'reason') || undefined;
      const result = await runtime.revocation.revokeKey({ signerKeyId, targetKeyId, reason });
      console.log(`key revocation statement: ${result.statementId}`);
      return;
    }

    case 'block-sdoc':
    case 'unblock-sdoc': {
      const targetSdocId = flag(flags, 'target') || positionals[0];
      if (!targetSdocId) throw new Error(`${command} requires --target <sdocId>`);
      const autoSigner = await resolveSdocSignerKey(runtime, targetSdocId);
      const signerKeyId = flag(flags, 'signer') || autoSigner || '';
      if (!signerKeyId) throw new Error(`no signer key: pass --signer <keyId>`);
      const reason = flag(flags, 'reason') || undefined;
      const result =
        command === 'block-sdoc'
          ? await runtime.revocation.blockSdoc({ signerKeyId, targetSdocId, reason })
          : await runtime.revocation.unblockSdoc({ signerKeyId, targetSdocId, reason });
      console.log(`${command} statement: ${result.statementId}`);
      return;
    }

    case 'import-tcert': {
      const input = positionals[0];
      if (!input) throw new Error('import-tcert <base64-or-file>');
      const bytes = readBytes(input);
      const parsed = parseSignedObject(bytes);
      const tcertId = tcertIdOf(parsed.signerKeyId, parsed.data.certificateNumber as number);
      await runtime.deps.certificateStore.save(tcertId, bytes);
      if (flag(flags, 'pin') === 'true' || flag(flags, 'pin') === 'yes' || hasFlagTrue(flags, 'pin')) {
        await runtime.trust.pin(tcertId);
      }
      console.log(`imported tcert: ${tcertId}`);
      if (flag(flags, 'pin')) console.log('pinned');
      return;
    }

    case 'export-tcert': {
      const tcertId = flag(flags, 'tcert') || positionals[0];
      if (!tcertId) throw new Error('export-tcert requires --tcert <id>');
      const bytes = await runtime.deps.certificateStore.get(tcertId);
      if (!bytes) throw new Error(`TCert not found: ${tcertId}`);
      console.log(toBase64Url(bytes));
      return;
    }

    case 'export-sdoc': {
      const sdocId = flag(flags, 'sdoc') || positionals[0];
      if (!sdocId) throw new Error('export-sdoc requires --sdoc <id>');
      const bytes = await runtime.deps.documentStore.get(sdocId);
      if (!bytes) throw new Error(`SDoc not found: ${sdocId}`);
      console.log(toBase64Url(bytes));
      return;
    }

    case 'list': {
      const kind = flag(flags, 'kind') || 'all';
      if (kind === 'tcert' || kind === 'all') {
        const tcerts = await runtime.deps.certificateStore.all();
        for (const { tcertId, bytes } of tcerts) {
          const parsed = parseSignedObject(bytes);
          const identity = parsed.data.identity as { name?: string } | undefined;
          console.log(`tcert ${tcertId}  name=${identity?.name ?? '?'}`);
        }
      }
      if (kind === 'key' || kind === 'all') {
        const keys = await runtime.deps.publicKeyStore.all();
        for (const k of keys) console.log(`key ${k.keyId}  ${k.algorithm}`);
      }
      if (kind === 'sdoc' || kind === 'all') {
        const docs = await runtime.deps.documentStore.all();
        for (const { sdocId } of docs) console.log(`sdoc ${sdocId}`);
      }
      return;
    }

    default:
      throw new Error(`Unknown command: ${command}`);
  }
}

function hasFlagTrue(flags: ParsedArgs['flags'], name: string): boolean {
  return flags[name] === true;
}

function printHelp(): void {
  console.log(`qrs-core ${VERSION} — SDoc Verification Protocol CLI

Usage: qrs <command> [options]

Key generation & certificates
  generate-key                Generate a key pair (Ed25519 or ECDSA-P256)
  create-tcert                Create a self-signed TCert (--fields-json to script it)
  import-tcert <b64|file>     Import a TCert (--pin to trust it)
  export-tcert --tcert <id>   Print a TCert as base64

Documents
  issue --tcert <id>          Issue an SDoc (--values-json to script it)
  verify <b64|file>           Verify an SDoc
  export-sdoc --sdoc <id>     Print an SDoc as base64

Trust management
  pin --tcert <id>            Trust a TCert directly
  unpin --tcert <id>          Remove direct trust
  add-ca --tcert <id>         Grant CA role to a TCert
  remove-ca --tcert <id>      Remove CA role
  distrust --tcert <id>       Locally distrust a TCert
  trust --tcert <id>          Remove local distrust
  attest --ca <id> --target <id> [--name <claim>]
  add-tcert --ca <id> --target <id> [--tcert-bytes <b64>]

Revocation
  revoke-tcert --target <id> [--signer <keyId>] [--type prospective|retrospective] [--reason <r>]
  revoke-key --target <keyId> [--signer <keyId>] [--reason <r>]
  block-sdoc --target <sdocId> [--signer <keyId>]
  unblock-sdoc --target <sdocId> [--signer <keyId>]

Other
  list [--kind tcert|sdoc|key]
  version

Scripting / automation
  --fields-json '<json>'      create-tcert: array of field schemas (no prompts)
  --values-json '<json>'      issue: object of field values (no prompts)
  --secret <k>=<v>[,<k>=<v>]  verify: supply secrets instead of prompting
  --location <lat,lon>        verify: supply the current location
  --time <epoch>              verify/create: override "now" (epoch seconds)

Options
  --data-dir <dir>   Where state is stored (default: ./.qrs-data, or $QRS_DATA_DIR)
`);
}

/** Entry point used by the `qrs` bin. */
export async function runCli(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  if (!command || command === 'help' || command === '--help' || command === '-h') {
    printHelp();
    return 0;
  }
  if (command === 'version' || command === '--version' || command === '-v') {
    console.log(VERSION);
    return 0;
  }
  const { positionals, flags } = parseArgs(rest);
  const dir = dataDirOf(flags);
  const runtime = buildRuntime(dir, flags);
  try {
    await dispatch(runtime, command, { positionals, flags });
    return 0;
  } catch (error) {
    console.error(`error: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }
}
