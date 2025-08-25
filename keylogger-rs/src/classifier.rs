// TODO: Implementar heurísticas simples para detectar
//       si el input parece ser login, password, tarjeta, etc.

pub fn classify_input(window_title: &str, text: &str) -> String {
    // Ejemplo de idea:
    // if text.contains("password") { "Possible password field" }
    // else if text.chars().all(|c| c.is_digit(10)) && text.len() == 16 { "Possible CC" }
    // else { "Generic input" }

    "TODO".to_string()
}
