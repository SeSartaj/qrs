/**
 * Shared terminal input. A single readline interface is reused across all prompts
 * (CLI + TerminalContextProvider). This keeps both interactive use and piped
 * (scripted) use working, because closing stdin between prompts would end the
 * process prematurely.
 */
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';

type Interface = ReturnType<typeof createInterface>;

let rl: Interface | null = null;
let closed = false;

export function getTerminalInterface(): Interface {
  if (!rl) {
    rl = createInterface({ input: stdin, output: stdout });
    rl.on('close', () => {
      closed = true;
    });
  }
  return rl;
}

/**
 * Ask a question and return the trimmed answer. If stdin reaches EOF while a
 * prompt is pending (e.g. scripted/piped input), the prompt resolves with `''`
 * instead of hanging forever.
 */
export async function terminalAsk(question: string): Promise<string> {
  if (closed) return '';
  const interface_ = getTerminalInterface();
  return new Promise<string>((resolve) => {
    const onClose = () => resolve('');
    interface_.once('close', onClose);
    interface_
      .question(question)
      .then(
        (answer) => {
          interface_.off('close', onClose);
          resolve(answer.trim());
        },
        () => {
          interface_.off('close', onClose);
          resolve('');
        }
      );
  });
}

/** Close the shared interface (call once, when the CLI is done). */
export function closeTerminalInterface(): void {
  if (rl) {
    rl.close();
    rl = null;
    closed = false;
  }
}
