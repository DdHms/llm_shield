const { startPrivacyProxy } = require('./llm-shield.node');

/**
 * Starts the Gemini Privacy Shield proxy.
 * This launches a FastAPI backend in a background thread and 
 * a native GUI window using pywebview.
 */
function run() {
  console.log('Starting Gemini Privacy Shield...');
  try {
    startPrivacyProxy();
  } catch (err) {
    console.error('Failed to start proxy:', err);
    process.exit(1);
  }
}

if (require.main === module) {
  run();
}

module.exports = { run };
