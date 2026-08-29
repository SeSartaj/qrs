import { AttachmentField } from './attachmentField.js';
import { DateField } from './dateField.js';
import { DateTimeField } from './datetimeField.js';
import { DatetimeEpochField } from './datetimeEpochField.js';
import { LocationField } from './locationField.js';
import { NumberField } from './numberField.js';
import { FieldRegistry } from './registry.js';
import { SecretInputField } from './secretInputField.js';
import { SelectField } from './selectField.js';
import { SelectV2Field } from './selectv2Field.js';
import { TextField } from './textField.js';
import { TextareaField } from './textareaField.js';

/** The reference field engines the implementation ships with. */
export function createDefaultFieldRegistry(): FieldRegistry {
  return new FieldRegistry([
    new TextField(),
    new TextareaField(),
    new SelectField(),
    new SelectV2Field(),
    new NumberField(),
    new DateField(),
    new DateTimeField(),
    new DatetimeEpochField(),
    new LocationField(),
    new SecretInputField(),
    new AttachmentField(),
  ]);
}

export {
  AttachmentField,
  DateField,
  DateTimeField,
  DatetimeEpochField,
  FieldRegistry,
  LocationField,
  NumberField,
  SecretInputField,
  SelectField,
  SelectV2Field,
  TextField,
  TextareaField,
};
export {
  ATTACHMENT_HASH_HEX,
  attachmentContentType,
  attachmentReference,
  verifyAttachmentReference,
  type AttachmentReference,
} from './attachmentField.js';
