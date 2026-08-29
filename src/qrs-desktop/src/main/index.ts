/**
 * Electron main process entry point.
 */
import { app, BrowserWindow } from 'electron';
import { join } from 'node:path';
import { writeFile } from 'node:fs/promises';
import { electronApp, optimizer } from '@electron-toolkit/utils';
import { createMainWindow } from './window.js';
import { createDesktopRuntime } from './runtime.js';
import { registerIpc } from './ipc.js';
import { runSmokeTest } from './smokeTest.js';
import { runSyncTest } from './syncTest.js';

// Pin the data directory so signing keys, certificates and documents persist in
// the SAME place in every mode. Without this, electron-builder's productName
// ("QRS Desktop") points the packaged app at a different userData dir than the
// dev/preview builds ("qrs-desktop"), so after switching modes the private key
// store would appear empty (the keys were never lost — they live elsewhere).
app.setPath('userData', join(app.getPath('appData'), 'qrs-desktop'));

let mainWindow: BrowserWindow | null = null;

function createWindow(): BrowserWindow {
  const win = createMainWindow();
  mainWindow = win;
  win.on('closed', () => {
    mainWindow = null;
    runtime?.context.cancelAll();
  });
  return win;
}

// The runtime is created after the first window exists so the context provider can
// forward location/secret prompts to the renderer.
let runtime: ReturnType<typeof createDesktopRuntime> | null = null;

app.whenReady().then(() => {
  electronApp.setAppUserModelId('org.qrs.desktop');

  // F12 toggles devtools, CmdOrCtrl+R reloads (dev only).
  app.on('browser-window-created', (_, window) => {
    optimizer.watchWindowShortcuts(window);
  });

  createWindow();
  runtime = createDesktopRuntime(() => mainWindow);
  registerIpc(runtime);

  // Headless self-test for CI: run the issue flow, print JSON, then quit.
  if (process.env['QRS_SMOKE_TEST'] === '1') {
    void (async () => {
      try {
        await runSmokeTest(runtime!);
        console.log('QRS_SMOKE_OK');
      } catch (error) {
        console.error('QRS_SMOKE_FAIL', error);
        process.exitCode = 1;
      } finally {
        app.quit();
      }
    })();
  }

  // Headless sync self-test: CA → attest → sync against a live server, print the
  // full result (including every error message), then quit.
  if (process.env['QRS_SYNC_TEST'] === '1') {
    void (async () => {
      try {
        await runSyncTest(runtime!);
      } catch (error) {
        console.error('QRS_SYNC_FAIL', error);
        process.exitCode = 1;
      } finally {
        app.quit();
      }
    })();
  }

  // Save a screenshot of the rendered UI (for visual checks / docs).
  if (process.env['QRS_SCREENSHOT']) {
    const target = process.env['QRS_SCREENSHOT'];
    const page = process.env['QRS_SCREENSHOT_PAGE'];
    const win = BrowserWindow.getAllWindows()[0];
    win.show();
    const grab = (): void => {
      void (async () => {
        try {
          await new Promise((r) => setTimeout(r, 800));
          const image = await win.webContents.capturePage();
          const png = image.toPNG();
          await writeFile(target, png);
          console.log('QRS_SCREENSHOT_SAVED ' + target + ' bytes=' + png.byteLength);
        } catch (error) {
          console.error('QRS_SCREENSHOT_FAIL', error);
          process.exitCode = 1;
        } finally {
          app.quit();
        }
      })();
    };
    const grabAfterNav = (): void => {
      // Support `documents:<tcertId>` to open a specific certificate for screenshots.
      let nav = page ? `window.__qrsGo?.(${JSON.stringify(page.split(':')[0] ?? page)});` : '';
      if (page?.startsWith('documents:')) {
        const tcertId = page.slice('documents:'.length);
        nav = `window.__qrsInitialTcert=${JSON.stringify(tcertId)}; ` + nav;
      }
      // For the Verify page screenshot, auto-load the first issued doc + verify so
      // the rendered attachment (if any) is visible.
      if (page === 'verify') nav = 'window.__qrsAutoVerify=true; ' + nav;
      const lang = process.env['QRS_SCREENSHOT_LANG'];
      const js = lang
        ? `try{localStorage.setItem('qrs.lang',${JSON.stringify(lang)});}catch(e){}window.location.reload();`
        : nav;
      if (js) void win.webContents.executeJavaScript(js).catch(() => undefined);
      setTimeout(grab, lang ? 2400 : page ? 1800 : 1200);
    };
    win.webContents.once('did-finish-load', grabAfterNav);
    // Fallback in case the load event already fired or capture is flaky.
    setTimeout(grabAfterNav, 5000);
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
