// TODO: Implementar heurísticas simples para detectar
//       si el input parece ser login, password, tarjeta, etc.
// Primero: saber sobre que software el usuario está escribiendo
// Luego: analizar el texto ingresado
// IDEA: utilizar alguna api de "accesibilidad" de windows para saber el contexto, así como los ciegos utilizan las computadoras
//       (por ejemplo, si el campo es de tipo password, o si el título de la ventana es "Login" o "Payment", etc.)
pub fn classify_input(window_title: &str, text: &str) -> String {
    // Ejemplo de idea:
    // if text.contains("password") { "Possible password field" }
    // else if text.chars().all(|c| c.is_digit(10)) && text.len() == 16 { "Possible CC" }
    // else { "Generic input" }

    "TODO".to_string()
}
