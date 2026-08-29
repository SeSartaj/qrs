import { beforeEach, describe, expect, it, vi } from 'vitest';

// A queue of answers the mocked readline returns for successive prompts.
let mockAnswers: string[] = [];
vi.mock('node:readline/promises', () => ({
  createInterface: () => ({
    question: vi.fn(async () => mockAnswers.shift() ?? ''),
    close: vi.fn(),
    on: vi.fn(),
    once: vi.fn(),
    off: vi.fn(),
  }),
}));

import { askFieldValue, buildSchemaInteractively } from '../src/cli/prompts.js';

describe('interactive schema builder (CLI prompts)', () => {
  beforeEach(() => {
    mockAnswers = [];
  });

  it('adds a location field when "location" is typed at the add-field prompt', async () => {
    // Prompt sequence:
    //  1. add-field prompt  -> "location" (field type typed directly)
    //  2. field name        -> "pharmacy_location"
    //  3. field label       -> "Pharmacy Location"
    //  4. maxRadius         -> "50"
    //  5. add-another-field -> "n" (finish)
    mockAnswers = ['location', 'pharmacy_location', 'Pharmacy Location', '50', 'n'];
    const fields = await buildSchemaInteractively();

    expect(fields).toHaveLength(1);
    expect(fields[0]).toMatchObject({
      type: 'location',
      name: 'pharmacy_location',
      label: 'Pharmacy Location',
      verifyRules: { maxRadius: 50 },
    });
  });

  it('keeps the classic flow: "y" then a field type', async () => {
    //  1. add-field prompt -> "y"
    //  2. field type       -> "text"
    //  3. name / label     -> ...
    //  4. minLength / maxLength / required (enter for all)
    //  5. add-another      -> "n"
    mockAnswers = ['y', 'text', 'name', 'Label', '', '', 'n', 'n'];
    const fields = await buildSchemaInteractively();
    expect(fields).toHaveLength(1);
    expect(fields[0]).toMatchObject({ type: 'text', name: 'name', label: 'Label' });
  });

  it('returns an empty schema when the user declines immediately', async () => {
    mockAnswers = ['n'];
    expect(await buildSchemaInteractively()).toEqual([]);
  });

  it('asks for coordinates when issuing a location field', async () => {
    mockAnswers = ['34.5553, 69.2075'];
    const value = await askFieldValue({ type: 'location', name: 'loc', label: 'Location' });
    expect(value).toEqual({ lat: 34.5553, lon: 69.2075 });
  });

  it('returns undefined for an empty location answer', async () => {
    mockAnswers = [''];
    const value = await askFieldValue({ type: 'location', name: 'loc', label: 'Location' });
    expect(value).toBeUndefined();
  });
});
