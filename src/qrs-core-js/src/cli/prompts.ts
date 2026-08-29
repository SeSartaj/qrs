/**
 * Interactive terminal prompts used by the CLI.
 */
import { terminalAsk } from '../context/terminalInput.js';
import { isFieldType, isRevocationType } from '../signedObject/schemas.js';
import type { AlgorithmId, FieldType, RevocationType } from '../types.js';
import type { FieldSchema } from '../fields/types.js';

export async function ask(question: string): Promise<string> {
  return terminalAsk(question);
}

export async function askOptional(question: string): Promise<string | undefined> {
  const answer = await ask(question);
  return answer.length > 0 ? answer : undefined;
}

export async function askYesNo(question: string, defaultValue = false): Promise<boolean> {
  const answer = (await ask(`${question} [${defaultValue ? 'Y/n' : 'y/N'}] `)).toLowerCase();
  if (answer === 'y' || answer === 'yes') return true;
  if (answer === 'n' || answer === 'no') return false;
  return defaultValue;
}

export async function askNumber(question: string): Promise<number | undefined> {
  const answer = await askOptional(question);
  if (answer === undefined) return undefined;
  const n = Number(answer);
  return Number.isFinite(n) ? n : undefined;
}

export async function askAlgorithm(defaultAlgorithm: AlgorithmId = 'Ed25519'): Promise<AlgorithmId> {
  const answer = (await ask(`Algorithm (Ed25519|ECDSA-P256) [${defaultAlgorithm}]: `)).trim();
  if (answer === 'Ed25519' || answer === 'ECDSA-P256') return answer;
  return defaultAlgorithm;
}

export async function askRevocationType(defaultType: RevocationType = 'prospective'): Promise<RevocationType> {
  const answer = (await ask(`Revocation type (prospective|retrospective) [${defaultType}]: `)).trim();
  if (isRevocationType(answer)) return answer;
  return defaultType;
}

const FIELD_TYPES_HINT = 'text|select|number|date|datetime|location|secretInput|attachment';

/** Interactively build a document schema (list of fields). */
export async function buildSchemaInteractively(): Promise<FieldSchema[]> {
  const fields: FieldSchema[] = [];
  for (;;) {
    // Accept a field type directly (e.g. "location"), y/yes, or n/no/empty.
    const hint =
      fields.length === 0
        ? `Add a document field (${FIELD_TYPES_HINT})? [Y/n] `
        : `Add another field (${FIELD_TYPES_HINT})? [y/N] `;
    const answer = (await ask(hint)).trim().toLowerCase();
    if (answer === '') {
      // First prompt defaults to yes; subsequent ones default to no.
      if (fields.length === 0) {
        const field = await askFieldSchema();
        if (field) fields.push(field);
        continue;
      }
      break;
    }
    if (answer === 'n' || answer === 'no') break;
    if (isFieldType(answer)) {
      // A field type was typed directly (e.g. "location"): add that field now.
      const field = await askFieldSchema(answer);
      if (field) fields.push(field);
      continue;
    }
    // 'y'/'yes' or any other value: add a field and ask for its type.
    const field = await askFieldSchema();
    if (field) fields.push(field);
  }
  return fields;
}

export async function askFieldSchema(preType?: FieldType): Promise<FieldSchema | null> {
  let type: FieldType;
  if (preType) {
    type = preType;
  } else {
    const typeRaw = (await ask(`Field type (${FIELD_TYPES_HINT}): `)).trim();
    if (!isFieldType(typeRaw)) {
      console.error(`Unknown field type: ${typeRaw}`);
      return null;
    }
    type = typeRaw as FieldType;
  }
  const name = await ask('Field name (machine, e.g. pharmacy_name): ');
  const label = await ask('Field label (human, e.g. Pharmacy Name): ');
  const field: FieldSchema = { type, name, label };

  switch (type) {
    case 'text': {
      const inputRules: Record<string, unknown> = {};
      const minLength = await askNumber('minLength (optional): ');
      const maxLength = await askNumber('maxLength (optional): ');
      const required = await askYesNo('Required?', false);
      if (minLength !== undefined) inputRules.minLength = minLength;
      if (maxLength !== undefined) inputRules.maxLength = maxLength;
      if (required) inputRules.required = true;
      field.inputRules = inputRules;
      break;
    }
    case 'select': {
      const options = (await ask('Options (comma separated): '))
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const required = await askYesNo('Required?', false);
      field.options = options;
      field.inputRules = required ? { required: true } : {};
      break;
    }
    case 'number': {
      const inputRules: Record<string, unknown> = {};
      const min = await askNumber('min (optional): ');
      const max = await askNumber('max (optional): ');
      if (min !== undefined) inputRules.min = min;
      if (max !== undefined) inputRules.max = max;
      field.inputRules = inputRules;
      break;
    }
    case 'location': {
      const radius = await askNumber('maxRadius in metres for verification (optional): ');
      if (radius !== undefined) field.verifyRules = { maxRadius: radius };
      break;
    }
    case 'secretInput': {
      const binding = (await ask('binding (stripped|inline) [stripped]: ')).trim();
      field.binding = binding === 'inline' ? 'inline' : 'stripped';
      break;
    }
    case 'attachment': {
      const contentType = await askOptional('contentType (e.g. image/png) [image/png]: ');
      field.inputRules = { contentType: contentType ?? 'image/png' };
      break;
    }
    case 'date':
    case 'datetime':
      break;
  }
  return field;
}

/** Prompt for the value of a single field at issuance time. */
export async function askFieldValue(field: FieldSchema): Promise<unknown> {
  switch (field.type) {
    case 'text':
      return (await askOptional(`${field.label} [${field.name}]: `)) ?? '';
    case 'select': {
      const answer = await ask(`${field.label} (${field.options?.join(' / ') ?? 'free'}): `);
      return answer;
    }
    case 'number': {
      const n = await askNumber(`${field.label}: `);
      return n;
    }
    case 'date':
      return (await ask(`${field.label} (YYYY-MM-DD): `)) || undefined;
    case 'datetime':
      return (await ask(`${field.label} (YYYY-MM-DDTHH:mm:ssZ): `)) || undefined;
    case 'location': {
      const answer = await askOptional(`${field.label} (lat,lon): `);
      if (!answer) return undefined;
      const parts = answer.split(',').map((s) => parseFloat(s.trim()));
      const lat = parts[0];
      const lon = parts[1];
      if (lat === undefined || lon === undefined || !Number.isFinite(lat) || !Number.isFinite(lon)) return undefined;
      return { lat, lon };
    }
    case 'secretInput':
      return ask(`${field.label} [${field.name}]: `);
    case 'attachment': {
      const id = await askOptional('Attachment object id: ');
      if (!id) return undefined;
      const contentType = await askOptional('contentType: ');
      const contentHash = await askOptional('contentHash (sha256 hex, 64 chars): ');
      return { id, contentType: contentType ?? 'image/png', contentHash: contentHash ?? '' };
    }
  }
}
