const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

/**
 * Verifies the integrity of the native binary.
 */
function verifyBinary(binaryPath, binaryName) {
  const checksumsPath = path.join(__dirname, 'checksums.json');
  if (!fs.existsSync(checksumsPath)) {
    console.warn('⚠️ No checksums.json found. Skipping integrity check.');
    return;
  }

  const checksums = JSON.parse(fs.readFileSync(checksumsPath, 'utf8'));
  const expectedHash = checksums[binaryName];

  if (!expectedHash || expectedHash === 'EXPECTED_HASH_HERE') {
    console.warn(`⚠️ No valid checksum found for ${binaryName}. Skipping integrity check.`);
    return;
  }

  const fileBuffer = fs.readFileSync(binaryPath);
  const hashSum = crypto.createHash('sha256');
  hashSum.update(fileBuffer);
  const actualHash = hashSum.digest('hex');

  if (actualHash !== expectedHash) {
    throw new Error(`
      🛑 BINARY INTEGRITY CHECK FAILED!
      File: ${binaryName}
      Expected Hash: ${expectedHash}
      Actual Hash:   ${actualHash}
      
      This could indicate a compromised binary or a build mismatch.
    `);
  }
}

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

  let chosenPath = '';
  let chosenName = '';

  if (fs.existsSync(binaryPath)) {
    chosenPath = binaryPath;
    chosenName = binaryName;
  } else if (fs.existsSync(fallbackPath)) {
    chosenPath = fallbackPath;
    chosenName = 'llm-shield.node';
  }

  if (chosenPath) {
    verifyBinary(chosenPath, chosenName);
    return require(chosenPath);
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
