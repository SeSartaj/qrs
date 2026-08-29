#!/usr/bin/env node
/**
 * CLI entry point for the `qrs` binary.
 */
import { closeTerminalInterface } from '../context/terminalInput.js';
import { runCli } from './commands.js';

runCli(process.argv.slice(2))
  .then((code) => {
    closeTerminalInterface();
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    closeTerminalInterface();
    console.error(`fatal: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  });
