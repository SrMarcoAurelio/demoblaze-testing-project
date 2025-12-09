# 📋 Guía de Reporte de Issues - ANDREA

## ⚠️ **IMPORTANTE - LEE ESTO PRIMERO**

Andrea, esta guía es **específica para ti**. Te explica exactamente cómo debes reportar issues y qué mentalidad debes tener como QA.

**Regla de Oro:** Tu trabajo NO es solo encontrar el bug específico que te asignan. Tu trabajo es **asegurar que TODO funcione correctamente**.

---

## 🎯 **Tu Rol Como QA**

### **¿Qué Significa Ser QA?**

Eres la **última línea de defensa** antes de que el software llegue a los usuarios. Si algo pasa desapercibido y llega a producción:

1. 👎 Los usuarios tendrán una mala experiencia
2. 👎 La empresa pierde credibilidad
3. 👎 Los managers preguntarán: **"¿Por qué QA no detectó esto?"**
4. 👎 **TÚ tendrás que explicar por qué no lo viste**

**Por eso:** Si algo te parece raro, no tiene sentido, o simplemente "se ve mal" → **REPÓRTALO**.

### **Mentalidad Correcta:**

❌ **MAL:** "Mi tarea dice 'testear login', así que solo voy a probar si el login funciona"

✅ **BIEN:** "Voy a testear login, pero también voy a revisar:
- ¿Los mensajes de error son claros?
- ¿Qué pasa si intento SQL injection?
- ¿Funciona en móvil?
- ¿Es accesible para personas con discapacidades?
- ¿Este botón tiene sentido?
- ¿Los colores cumplen con estándares?"

---

## 🔍 **Metodología de Testing**

### **Problema Planteado:**

Cuando te asignan una tarea tipo: "Testear funcionalidad de login"

### **Tu Proceso:**

#### **1. Entender el Problema**

```
¿Qué estoy testeando?: Login
¿Qué debería pasar?: Usuarios deberían poder entrar con credenciales válidas
¿Qué NO debería pasar?: Usuarios no deberían entrar con credenciales inválidas
```

#### **2. Criterios de Prueba**

No solo pruebes el "happy path" (el caso ideal). Prueba:

**Funcionalidad Básica:**
- ✅ Login con credenciales válidas → Funciona
- ✅ Login con credenciales inválidas → Muestra error claro
- ✅ Login con campos vacíos → Validación apropiada
- ✅ Login con usuario que no existe → Error apropiado
- ✅ Login con contraseña incorrecta → Error apropiado

**Seguridad:**
- ✅ Intento de SQL injection → ¿Está protegido?
- ✅ Contraseña visible → ¿Se muestra como puntos?
- ✅ Error específico → ¿Revela si el usuario existe? (problema de seguridad)

**Usabilidad:**
- ✅ Mensaje de error → ¿Es claro para el usuario?
- ✅ Botón "Olvidé contraseña" → ¿Funciona?
- ✅ Checkbox "Recordarme" → ¿Persiste la sesión?
- ✅ Logout → ¿Limpia la sesión correctamente?

**Accesibilidad:**
- ✅ Navegación con teclado → ¿Funciona Tab + Enter?
- ✅ Lector de pantalla → ¿Anuncia los elementos?
- ✅ Contraste de colores → ¿Es suficiente?

**Performance:**
- ✅ Tiempo de respuesta → ¿Es rápido?
- ✅ Múltiples intentos → ¿Se maneja bien?

#### **3. Descubrir Nuevos Issues**

**Ejemplo Real:**

```
Te asignan: "Bug #123 - Botón login no responde"

TU TESTING:
1. ✅ Verificas que el botón ahora funciona (bug arreglado)
2. 🔍 PERO NOTAS: La contraseña se muestra en texto plano (CRÍTICO!)
3. 🔍 TAMBIÉN NOTAS: No hay validación de campo vacío
4. 🔍 ADEMÁS NOTAS: El link "Olvidé contraseña" está roto
5. 🔍 Y ENCUENTRAS: El mensaje de error revela si el usuario existe (seguridad)

RESULTADO:
- Bug asignado: ✅ Corregido
- Nuevos issues críticos: 🐛🐛🐛🐛 Encontraste 4 más!
```

**¿Ves la diferencia?** No solo verificaste que el bug fue arreglado. **Exploraste y encontraste más problemas.**

---

## 📝 **Cómo Reportar Issues**

### **Estructura del Reporte:**

```markdown
## 🐛 [Componente] Título Claro y Específico

**Prioridad:** CRÍTICA / ALTA / MEDIA / BAJA
**Tipo:** Bug / Mejora / Pregunta / Violación de Estándares

### Descripción del Problema
[Explica QUÉ está mal, sin tecnicismos innecesarios pero siendo específica]

### Ambiente de Prueba
- Navegador: Chrome 120 / Firefox 115 / Safari 17
- Sistema Operativo: Windows 11 / macOS Sonoma / Ubuntu 22.04
- Resolución: 1920x1080 / 1366x768 / 375x667 (móvil)
- Rol de Usuario: Admin / Usuario Normal / Invitado

### Comportamiento Esperado
[Qué DEBERÍA pasar según los requisitos o el sentido común]

### Comportamiento Actual
[Qué REALMENTE pasa - sé específica]

### Pasos para Reproducir
1. Ir a página de login
2. Ingresar usuario: "test@test.com"
3. Ingresar contraseña: "123456"
4. Hacer clic en "Iniciar Sesión"
5. Observar: [lo que pasa]

### Evidencia
- 📸 Screenshot: [adjuntar]
- 🎥 Video: [si es complejo, grabar pantalla]
- 🔍 Console Error: [abrir DevTools F12, copiar errores]
- 📊 Network: [si hay error de API]

### Impacto
[¿Cómo afecta esto a los usuarios? ¿Cuántos usuarios afecta?]

### Contexto Adicional
- ¿Cuándo lo notaste?: 09/12/2024 10:30
- ¿Está relacionado con un deploy reciente?: Sí/No
- ¿Hay workaround?: Sí/No - [explicar si hay]
- ¿Qué estándares viola?: WCAG 2.1 / Diseño / Seguridad

### Preguntas para IT (si aplica)
1. ¿Este botón debería hacer algo?
2. ¿Este comportamiento es intencional?
3. ¿Por qué está este elemento aquí?
```

---

## 💡 **Ejemplos de Situaciones Reales**

### **Ejemplo 1: Botón Sin Función**

**Situación:** Estás testeando el carrito de compras y ves un botón que dice "Guardar para después"

**Lo que haces:**
1. Haces clic en el botón
2. No pasa nada
3. No hay feedback visual
4. No se guarda nada

**Reportes:**

```markdown
## 🐛 [Carrito] Botón "Guardar para después" no tiene funcionalidad

**Prioridad:** MEDIA
**Tipo:** Pregunta / Potencial Bug

### Descripción
El botón "Guardar para después" en la página del carrito no hace nada
cuando se hace clic. No hay feedback visual, no se guardan items, no hay error.

### Preguntas para IT:
1. ¿Este botón debería tener funcionalidad?
2. Si SÍ → Es un bug que hay que arreglar
3. Si NO → Debería removerse (confunde a usuarios)
4. Si es para implementación futura → Debería estar deshabilitado con tooltip

### Comportamiento Actual
- Click en botón → Nada pasa
- Sin feedback visual
- Sin mensaje de error
- Sin funcionalidad aparente

### Impacto
- Usuarios hacen clic esperando funcionalidad
- Se confunden cuando no pasa nada
- Mala experiencia de usuario

### Recomendación
Opción A: Implementar funcionalidad
Opción B: Remover botón hasta que esté listo
Opción C: Deshabilitar con mensaje "Próximamente"
```

**¿Por qué reportarlo?** Porque si un jefe pregunta "¿Por qué tenemos un botón que no hace nada?" y TÚ lo testeaste, necesitas demostrar que sí lo notaste y reportaste.

### **Ejemplo 2: Validación de Campo**

**Situación:** Testeas formulario de registro

**Observación:** El campo "Email" acepta "abc123" sin @

**Reporte:**

```markdown
## 🐛 [Registro] Campo Email acepta formato inválido

**Prioridad:** ALTA
**Tipo:** Bug - Validación

### Descripción
El campo "Email" en formulario de registro acepta entradas que no son
emails válidos (ej: "abc123", "test", "email.com").

### Comportamiento Esperado
- Solo aceptar emails válidos: usuario@dominio.com
- Mostrar error si formato es inválido
- Validar antes de permitir submit

### Comportamiento Actual
- Acepta cualquier texto
- No valida formato
- Permite registro con email inválido
- Backend probablemente rechaza, pero frontend debería validar primero

### Pasos para Reproducir
1. Ir a página de registro
2. En campo "Email" ingresar: "abc123"
3. Hacer clic en "Registrarse"
4. Observar: Se acepta sin error

### Impacto
- Usuarios registran emails inválidos
- No pueden recuperar contraseña
- Datos sucios en base de datos
- Mala experiencia de usuario

### Evidencia
[Screenshot del campo aceptando "abc123"]

### Estándares Violados
- HTML5: Input type="email" debería validar automáticamente
- UX: Validación debe ser inmediata (no esperar submit)

### Sugerencia
Agregar:
- Validación regex: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
- Mensaje de error claro: "Por favor ingresa un email válido"
- Validación en tiempo real (mientras escribe)
```

### **Ejemplo 3: Violación de Accesibilidad**

**Situación:** Testeas catálogo de productos

**Observación:** Las imágenes no tienen texto alternativo

**Reporte:**

```markdown
## ♿ [Accesibilidad] Imágenes de productos sin texto alternativo - WCAG 2.1

**Prioridad:** ALTA (Problema legal de compliance)
**Tipo:** Violación de Estándares

### Descripción
Todas las imágenes de productos en el catálogo no tienen atributo 'alt'.
Esto viola WCAG 2.1 Level A (1.1.1 Non-text Content).

### Impacto
- Usuarios con lectores de pantalla no pueden entender qué productos son
- Viola leyes de accesibilidad (ADA, Section 508)
- Potencial demanda legal
- Mala experiencia para usuarios con discapacidades visuales
- Impacto SEO negativo

### Código Actual (Incorrecto)
```html
<img src="samsung-galaxy-s23.jpg">
```

### Código Esperado (Correcto)
```html
<img src="samsung-galaxy-s23.jpg"
     alt="Samsung Galaxy S23 - Negro, 256GB, Pantalla 6.1 pulgadas">
```

### Estándares Violados
- WCAG 2.1 Level A: 1.1.1 Non-text Content
- Section 508: § 1194.22(a)
- EN 301 549: 9.1.1.1

### Evidencia
- Inspeccionar elemento muestra <img> sin atributo alt
- Lector de pantalla solo dice "Imagen" sin contexto

### Recomendación
Agregar texto alternativo descriptivo a TODAS las imágenes:
Format: "[Marca] [Modelo] - [Características clave]"

Ejemplo: "iPhone 15 Pro Max - Titanio Azul, 512GB, Cámara 48MP"
```

---

## ⚠️ **Casos Donde DEBES Reportar (Aunque no esté en tu tarea)**

### **1. Elementos Sin Sentido**

Si ves:
- Un botón que no hace nada
- Un campo que parece innecesario
- Un mensaje confuso
- Un elemento fuera de lugar

**→ REPÓRTALO** con pregunta: "¿Esto debería estar aquí?"

### **2. Violaciones de Estándares**

Si ves:
- Contraste de color pobre (texto gris sobre fondo gris claro)
- Botones demasiado pequeños en móvil
- Textos que no se leen bien
- Imágenes sin alt text
- Navegación que no funciona con teclado

**→ REPÓRTALO** como violación de WCAG 2.1

### **3. Mala Experiencia de Usuario**

Si ves:
- Mensajes de error confusos
- Proceso complicado innecesariamente
- Diseño inconsistente
- Navegación poco clara

**→ REPÓRTALO** como mejora de UX

### **4. Potenciales Problemas de Seguridad**

Si ves:
- Contraseñas visibles
- URLs con información sensible
- Errores que revelan información del sistema
- Posibilidad de inyección (SQL, XSS)

**→ REPÓRTALO INMEDIATAMENTE** como CRÍTICO

---

## ✅ **Checklist para Cada Feature**

Cuando testes CUALQUIER feature, usa este checklist:

### **Funcionalidad:**
- [ ] ¿Funciona el happy path? (caso ideal)
- [ ] ¿Funciona con datos inválidos?
- [ ] ¿Funciona con campos vacíos?
- [ ] ¿Funciona con caracteres especiales?
- [ ] ¿Los mensajes de error son claros?

### **Seguridad:**
- [ ] ¿Hay validación de input?
- [ ] ¿Está protegido contra SQL injection?
- [ ] ¿Está protegido contra XSS?
- [ ] ¿Las contraseñas están ocultas?
- [ ] ¿Los errores no revelan información sensible?

### **Accesibilidad:**
- [ ] ¿Funciona con teclado (Tab, Enter, Esc)?
- [ ] ¿Hay suficiente contraste de color?
- [ ] ¿Los botones son suficientemente grandes?
- [ ] ¿Las imágenes tienen alt text?
- [ ] ¿Los lectores de pantalla lo leen correctamente?

### **Usabilidad:**
- [ ] ¿Es intuitivo para el usuario?
- [ ] ¿Los labels son claros?
- [ ] ¿El flujo tiene sentido?
- [ ] ¿Los botones están bien ubicados?
- [ ] ¿El diseño es consistente?

### **Performance:**
- [ ] ¿Carga rápido? (< 3 segundos)
- [ ] ¿Responde rápido a acciones?
- [ ] ¿Maneja bien múltiples acciones?

### **Responsive:**
- [ ] ¿Se ve bien en desktop?
- [ ] ¿Se ve bien en tablet?
- [ ] ¿Se ve bien en móvil?
- [ ] ¿Los botones son clickeables en pantalla pequeña?

---

## 🎯 **Recordatorios Importantes**

### **Cuando Estés Testeando:**

✅ **SIEMPRE PIENSA:** "Si yo fuera el usuario, ¿esto tendría sentido?"

✅ **SIEMPRE PREGUNTA:** "¿Qué más podría romperseaquí?"

✅ **SIEMPRE DOCUMENTA:** Screenshots, pasos, evidencia

✅ **SIEMPRE REPORTA:** Mejor reportar de más que de menos

### **Lo Que NO Debes Hacer:**

❌ **"No está en mi test case, no lo reporto"** → MAL
✅ **"No está en mi test case, pero es un problema, lo reporto"** → BIEN

❌ **"Es solo cosmético, no importa"** → MAL
✅ **"Es cosmético pero confunde usuarios, lo reporto como LOW"** → BIEN

❌ **"No entiendo para qué sirve esto, lo ignoro"** → MAL
✅ **"No entiendo para qué sirve esto, pregunto a IT"** → BIEN

❌ **"Funciona en mi máquina, está bien"** → MAL
✅ **"Funciona en mi máquina, pero lo pruebo en otros navegadores/dispositivos"** → BIEN

---

## 🚨 **Regla de Oro**

> **"Si un jefe pregunta '¿Cómo pasó esto desapercibido?',
> debes poder demostrar que TÚ SÍ lo notaste y reportaste."**

### **Protégete a Ti Misma:**

1. **Documenta TODO** → Screenshots, reportes, emails
2. **Pregunta cuando tengas dudas** → "¿Esto debería estar así?"
3. **Reporta todo lo sospechoso** → Mejor preguntar que asumir
4. **Guarda evidencia** → Tus reportes son tu respaldo

### **Protege al Producto:**

1. **Piensa como usuario** → ¿Esto confundiría a alguien?
2. **Piensa como hacker** → ¿Cómo podría romper esto?
3. **Piensa como diseñador** → ¿Esto se ve bien? ¿Es usable?
4. **Piensa como abogado** → ¿Cumple con estándares legales?

---

## 📞 **¿Dudas?**

### **¿Debo reportar esto?**

**Pregúntate:**
1. ¿Confundiría a un usuario? → SÍ: Repórtalo
2. ¿Podría causar problemas? → SÍ: Repórtalo
3. ¿No cumple estándares? → SÍ: Repórtalo
4. ¿No estoy segura? → Repórtalo con tag de pregunta

### **¿Cómo priorizo?**

- **CRÍTICO**: No funciona, pérdida de datos, seguridad comprometida
- **ALTO**: Feature importante rota, difícil workaround
- **MEDIO**: Funciona pero con problemas, hay workaround
- **BAJO**: Cosmético, menor, fácil workaround

**Si dudas entre dos prioridades, elige la MÁS ALTA.** Los managers pueden bajarla, pero es mejor ser precavido.

---

## 🎓 **Resumen para Andrea**

1. **Tu trabajo es asegurar calidad, no solo encontrar bugs específicos**
2. **Explora, descubre, cuestiona todo**
3. **Documenta TODO con evidencia**
4. **Reporta TODO lo sospechoso**
5. **Mejor reportar de más que de menos**
6. **Protégete con documentación**
7. **Piensa siempre en el usuario final**

**Pregunta Clave:** ¿Si tu nombre está asociado con este release y algo sale mal, podrás demostrar que hiciste tu trabajo correctamente?

**Si la respuesta es SÍ → Estás haciendo bien tu trabajo.**
**Si la respuesta es NO → Documenta más, reporta más, pregunta más.**

---

*Última Actualización: 09/12/2024*
*Versión: 1.0 - Andrea*
*Creado específicamente para: Andrea - QA Team*

**¿Preguntas? No dudes en preguntar al equipo de desarrollo o QA Lead.**
