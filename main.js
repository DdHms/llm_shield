const { app, BrowserWindow } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');

let mainWindow;
let pythonProcess;

function createWindow() {
  // 1. Create the browser window
  mainWindow = new BrowserWindow({
    width: 900,
    height: 700,
    title: "Gemini Privacy Shield",
    backgroundColor: '#0f172a', // Slate-900 matching our UI
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true
    }
  });

  // 2. Hide the default menu bar
  mainWindow.setMenuBarVisibility(false);

  // 3. Load our FastAPI-provided UI
  // We add a small delay to ensure the server has time to boot
  setTimeout(() => {
    mainWindow.loadURL('http://127.0.0.1:8080/ui');
  }, 2000);

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function startPythonEngine() {
  const isWin = os.platform() === 'win32';
  const binaryName = isWin ? 'privacy_shield.exe' : 'privacy_shield';
  
  // path logic to find the binary whether in dev or packaged app
  let enginePath;
  if (app.isPackaged) {
    // In production, electron-builder moves 'extraResources' to resourcesPath
    enginePath = path.join(process.resourcesPath, 'engine', binaryName);
  } else {
    // In development, we expect it in the local /engine folder
    enginePath = path.join(__dirname, 'engine', binaryName);
  }

  console.log(`Starting engine at: ${enginePath}`);

  // Spawn the background process
  pythonProcess = spawn(enginePath, [], {
    windowsHide: true, // Don't show a cmd window on Windows
  });

  pythonProcess.stdout.on('data', (data) => {
    console.log(`[Python] ${data}`);
  });

  pythonProcess.stderr.on('data', (data) => {
    console.error(`[Python Error] ${data}`);
  });
}

// Ensure the background engine is killed when Electron exits
function killPythonEngine() {
  if (pythonProcess) {
    if (os.platform() === 'win32') {
      spawn("taskkill", ["/pid", pythonProcess.pid, "/f", "/t"]);
    } else {
      pythonProcess.kill();
    }
    pythonProcess = null;
  }
}

app.whenReady().then(() => {
  startPythonEngine();
  createWindow();
});

app.on('window-all-closed', () => {
  killPythonEngine();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

app.on('will-quit', () => {
  killPythonEngine();
});
