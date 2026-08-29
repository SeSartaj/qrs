import type { FieldType } from '../types.js';
import { QrsUnsupportedError } from '../errors.js';
import type { IFieldEngine } from './types.js';

/** Registry of field engines keyed by field type. */
export class FieldRegistry {
  private readonly engines = new Map<FieldType, IFieldEngine>();

  constructor(engines: IFieldEngine[] = []) {
    for (const engine of engines) this.register(engine);
  }

  register(engine: IFieldEngine): this {
    this.engines.set(engine.type, engine);
    return this;
  }

  get(type: FieldType): IFieldEngine {
    const engine = this.engines.get(type);
    if (!engine) throw new QrsUnsupportedError(`Unsupported field type: ${type}`);
    return engine;
  }

  has(type: FieldType): boolean {
    return this.engines.has(type);
  }

  list(): IFieldEngine[] {
    return [...this.engines.values()];
  }
}
