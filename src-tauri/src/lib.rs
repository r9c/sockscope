#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use tauri::Manager; // brings .path() into scope
use tauri::path::BaseDirectory;

#[tauri::command]
fn scan(app: tauri::AppHandle) -> Result<String, String> {
  let dev_script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources/scanner.py");

  let script_path = if dev_script.exists() {
    dev_script
  } else {
    app.path()
      .resolve("resources/scanner.py", BaseDirectory::Resource)
      .map_err(|e| format!("resolve resource failed: {e}"))?
  };

  let output = std::process::Command::new("python3")
    .arg(&script_path)
    .output()
    .map_err(|e| format!("spawn python3 failed: {e}"))?;

  if !output.status.success() {
    return Err(format!(
      "scanner exited with {:?}\nstdout: {}\nstderr: {}",
      output.status.code(),
      String::from_utf8_lossy(&output.stdout),
      String::from_utf8_lossy(&output.stderr)
    ));
  }

  Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[tauri::command]
fn kill_pid(pid: i32) -> Result<(), String> {
  let status = std::process::Command::new("kill")
    .arg("-TERM")
    .arg(pid.to_string())
    .status()
    .map_err(|e| e.to_string())?;
  if status.success() { Ok(()) } else { Err(format!("kill exited with {status:?}")) }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .invoke_handler(tauri::generate_handler![scan, kill_pid])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
