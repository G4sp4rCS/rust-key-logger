use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use winapi::shared::minwindef::DWORD;
use winapi::um::winuser::{GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::GetModuleBaseNameW;
use winapi::um::winnt::PROCESS_QUERY_INFORMATION;
use winapi::um::handleapi::CloseHandle;

/// Información sobre el proceso activo
#[derive(Debug, Clone)]
pub struct ActiveProcessInfo {
    pub process_name: String,
    pub window_title: String,
    pub process_id: DWORD,
    pub window_handle: winapi::shared::windef::HWND,
}

/// Obtener información completa del proceso activo
pub fn get_active_process_info() -> Result<ActiveProcessInfo, Box<dyn std::error::Error>> {
    unsafe {
        // Obtener la ventana activa
        let hwnd = GetForegroundWindow();
        if hwnd.is_null() {
            return Err("No active window found".into());
        }
        
        // Obtener el título de la ventana
        let mut window_title = [0u16; 512];
        let title_len = GetWindowTextW(hwnd, window_title.as_mut_ptr(), window_title.len() as i32);
        let window_title_str = if title_len > 0 {
            let title_slice = &window_title[..title_len as usize];
            OsString::from_wide(title_slice).to_string_lossy().to_string()
        } else {
            "No Title".to_string()
        };
        
        // Obtener el ID del proceso
        let mut process_id: DWORD = 0;
        GetWindowThreadProcessId(hwnd, &mut process_id);
        
        if process_id == 0 {
            return Err("Could not get process ID".into());
        }
        
        // Abrir el proceso para obtener información
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, process_id);
        if process_handle.is_null() {
            return Ok(ActiveProcessInfo {
                process_name: "Unknown Process".to_string(),
                window_title: window_title_str,
                process_id,
                window_handle: hwnd,
            });
        }
        
        // Obtener el nombre del proceso
        let mut process_name = [0u16; 256];
        let name_len = GetModuleBaseNameW(
            process_handle,
            std::ptr::null_mut(),
            process_name.as_mut_ptr(),
            process_name.len() as DWORD,
        );
        
        CloseHandle(process_handle);
        
        let process_name_str = if name_len > 0 {
            let name_slice = &process_name[..name_len as usize];
            OsString::from_wide(name_slice).to_string_lossy().to_string()
        } else {
            "Unknown".to_string()
        };
        
        Ok(ActiveProcessInfo {
            process_name: process_name_str,
            window_title: window_title_str,
            process_id,
            window_handle: hwnd,
        })
    }
}

/// Versión simple que retorna tuple (para compatibilidad con código existente)
pub fn check_active_process() -> Result<(String, String), Box<dyn std::error::Error>> {
    let info = get_active_process_info()?;
    Ok((info.process_name, info.window_title))
}

/// Verificar si el proceso actual es sensible
pub fn is_sensitive_process(process_info: &ActiveProcessInfo) -> bool {
    let process_lower = process_info.process_name.to_lowercase();
    let title_lower = process_info.window_title.to_lowercase();
    
    // Procesos sensibles conocidos
    let sensitive_processes = [
        "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe",
        "whatsapp.exe", "telegram.exe", "slack.exe", "discord.exe",
        "teams.exe", "zoom.exe", "skype.exe", "signal.exe",
        "keepass.exe", "1password.exe", "bitwarden.exe",
        "outlook.exe", "thunderbird.exe",
        "notepad.exe", "code.exe", "notepad++.exe",
    ];
    
    // Keywords sensibles en títulos
    let sensitive_keywords = [
        "login", "sign in", "password", "register", "authentication",
        "log in", "signin", "signup", "sign up", "enter password",
        "user name", "username", "email", "gmail", "outlook",
        "facebook", "twitter", "instagram", "linkedin",
        "bank", "banking", "paypal", "credit card", "payment",
        "billing", "checkout", "financial", "account"
    ];
    
    // Verificar procesos
    for process in &sensitive_processes {
        if process_lower.contains(process) {
            return true;
        }
    }
    
    // Verificar keywords en título
    for keyword in &sensitive_keywords {
        if title_lower.contains(keyword) {
            return true;
        }
    }
    
    false
}