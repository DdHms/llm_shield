const path = require('path');
const fs = require('fs');

/**
 * Automates finding and loading the correct native binary for the user's OS.
 */
function loadBinding() {
  const { platform, arch } = process;
  let binaryName = '';

  if (platform === 'win32' && arch === 'x64') {
    binaryName = 'llm-shield.x86_64-pc-windows-msvc.node';
  } else if (platform === 'darwin' && arch === 'x64') {
    binaryName = 'llm-shield.x86_64-apple-darwin.node';
  } else if (platform === 'darwin' && arch === 'arm64') {
    binaryName = 'llm-shield.aarch64-apple-darwin.node';
  } else {
    // Fallback to the generic name if it exists (e.g. from a local build)
    binaryName = 'llm-shield.node';
  }

  const binaryPath = path.join(__dirname, binaryName);
  const fallbackPath = path.join(__dirname, 'llm-shield.node');

  if (fs.existsSync(binaryPath)) {
    return require(binaryPath);
  } else if (fs.existsSync(fallbackPath)) {
    return require(fallbackPath);
  } else {
    throw new Error(`
      No compatible native binary found for your system (${platform}-${arch}). 
      Please ensure you have placed the .node files from GitHub Actions into the project root.
    `);
  }
}

const { startPrivacyProxy } = loadBinding();

/**
 * Starts the LLM Shield proxy.
 */
function run() {
  console.log('🛡️ Starting LLM Shield...');
  try {
    startPrivacyProxy();
  } catch (err) {
    console.error('❌ Failed to start proxy:', err);
    process.exit(1);
  }
}

if (require.main === module) {
  run();
}

module.exports = { run };
