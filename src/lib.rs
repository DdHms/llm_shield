use napi_derive::napi;
use pyo3::prelude::*;
use pyo3::types::PyModule;
use std::env;

#[napi]
pub fn start_privacy_proxy() -> napi::Result<()> {
    // 1. Initialize Python Interpreter
    pyo3::prepare_freethreaded_python();

    Python::with_gil(|py| {
        // 2. Add current directory to sys.path so we can find proxy.py
        let sys = py.import("sys").map_err(|e| {
            napi::Error::from_reason(format!("Failed to import sys: {}", e))
        })?;
        let path: &pyo3::types::PyList = sys.getattr("path").unwrap().downcast().unwrap();
        
        // Get the directory where the binary is or the current working directory
        let current_dir = env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        path.insert(0, current_dir.to_str().unwrap()).map_err(|e| {
            napi::Error::from_reason(format!("Failed to update sys.path: {}", e))
        })?;

        // 3. Load the proxy.py module
        let proxy_module = PyModule::import(py, "proxy").map_err(|e| {
            napi::Error::from_reason(format!("Failed to import proxy.py. Ensure it's in the same directory as the binary or current path. Error: {}", e))
        })?;

        // 4. Call the main function that starts the server and GUI
        proxy_module.call_method0("run_application").map_err(|e| {
            napi::Error::from_reason(format!("Failed to call run_application in proxy.py: {}", e))
        })?;

        Ok(())
    })
}
