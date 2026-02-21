# IOC Utility Suite

Repositorio con herramientas web simples para generar configuraciones relacionadas con IoC (Indicators of Compromise) en distintos fabricantes de firewall.

⚠️ Estas herramientas **no ejecutan cambios automáticos**, solo generan texto para copiar y pegar manualmente en los equipos correspondientes.

---

## 🔹 Herramientas incluidas

### 1️⃣ Check Point IoC CSV Builder
Genera archivos CSV con formato estructurado para carga masiva de indicadores en entornos Check Point.

- Estandariza nombres
- Permite agregar comentarios
- Facilita importaciones ordenadas

---

### 2️⃣ Generador de CLI por Vendor
Genera comandos manuales para:

- 🟠 Palo Alto
- 🟢 FortiGate
- 🔵 Firepower (FMC – checklist)

Permite ingresar:
- IP
- Comentario (ticket / motivo)
- Grupo de bloqueo
- Opciones de formato de nombre

Entrega:
- Comandos listos para copiar y pegar
- Checklist cuando corresponde
- Registro local opcional en el navegador

---

## 🎯 Objetivo

Reducir errores manuales, estandarizar nombres y acelerar bloqueos sin necesidad de automatización directa ni integración con los firewalls.

---

## 🔐 Seguridad

- No utiliza credenciales
- No se conecta a dispositivos
- No almacena información sensible en servidores
- Solo genera texto localmente en el navegador

---

## 📌 Uso

1. Acceder a la herramienta correspondiente.
2. Completar los campos requeridos.
3. Copiar el resultado generado.
4. Aplicar manualmente en el firewall o consola de gestión.

---

## 📎 Licencia

Uso libre con fines educativos y operativos.
