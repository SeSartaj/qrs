import { describe, expect, it } from 'vitest';
import { extensionFor, fileNameFor } from '../src/main/attachments.js';

describe('attachment file helpers', () => {
  it('maps content types to file extensions and builds filenames', () => {
    expect(extensionFor('image/png')).toBe('png');
    expect(extensionFor('application/pdf')).toBe('pdf');
    expect(extensionFor('text/plain')).toBe('txt');
    expect(extensionFor('application/octet-stream')).toBe('bin');
    expect(fileNameFor('abcd'.repeat(8), 'application/pdf')).toMatch(/^abcdabcdabcdabcd\.pdf$/);
    expect(fileNameFor('abcd'.repeat(8), 'application/octet-stream')).toMatch(/^abcdabcdabcdabcd\.bin$/);
  });
});
