# Guía de Reporte de Issues - Estándares de QA
**Documento para: Andrea - Quality Assurance Analyst**

## Tabla de Contenidos
1. [Introducción](#introducción)
2. [Responsabilidades del Analista de QA](#responsabilidades-del-analista-de-qa)
3. [Metodología de Testing](#metodología-de-testing)
4. [Estructura del Reporte de Defectos](#estructura-del-reporte-de-defectos)
5. [Criterios de Cobertura de Testing](#criterios-de-cobertura-de-testing)
6. [Clasificación de Severidad y Prioridad](#clasificación-de-severidad-y-prioridad)
7. [Ejemplos de Casos Reales](#ejemplos-de-casos-reales)
8. [Referencias y Estándares](#referencias-y-estándares)

---

## Introducción

Este documento establece los estándares profesionales para la identificación, documentación y reporte de defectos de software según las mejores prácticas de la industria (ISTQB, IEEE 829, ISO/IEC 25010).

### Alcance Profesional

El rol de Analista de Quality Assurance requiere:
- Verificación sistemática de requisitos funcionales
- Investigación exploratoria más allá de casos de prueba predefinidos
- Validación de cumplimiento de estándares (accesibilidad, seguridad, rendimiento)
- Documentación técnica precisa de todos los hallazgos

### Responsabilidad Profesional

La calidad del software depende directamente de la rigurosidad en la detección y documentación de defectos. La documentación completa sirve como evidencia de due diligence profesional y protege tanto al proyecto como al analista de QA.

---

## Responsabilidades del Analista de QA

### 1. Verificación de Requisitos

**Validación Funcional:**
- Verificar que la funcionalidad cumple con especificaciones documentadas
- Identificar discrepancias entre requisitos y implementación
- Validar criterios de aceptación definidos
- Documentar ambigüedades en requisitos

**Testing Exploratorio:**
El testing exploratorio es una responsabilidad crítica que va más allá de la ejecución de test cases predefinidos. Incluye:
- Investigación de casos límite y condiciones de borde
- Identificación de problemas de integración entre componentes
- Descubrimiento de defectos no anticipados
- Análisis de comportamientos inesperados

### 2. Validación de Cumplimiento de Estándares

**Estándares de Accesibilidad (WCAG 2.1):**
- Nivel A: Requisitos mínimos obligatorios
- Nivel AA: Estándar de industria (objetivo)
- Nivel AAA: Nivel mejorado (implementar donde sea posible)

Criterios específicos a verificar:
- Alternativas textuales para contenido no textual (1.1.1)
- Relación de contraste suficiente (1.4.3)
- Navegación por teclado completa (2.1.1)
- Identificación de errores clara (3.3.1)

**Estándares de Seguridad (OWASP Top 10):**
- Inyección (SQL, XSS, Command)
- Autenticación rota
- Exposición de datos sensibles
- Control de acceso roto
- Configuración incorrecta de seguridad

**Estándares de Rendimiento:**
- Core Web Vitals de Google
- Tiempos de carga según SLA/SLO definidos
- Respuesta de API dentro de umbrales establecidos

### 3. Análisis de Riesgo e Impacto

Al identificar un defecto, evaluar:

**Impacto Técnico:**
- Estabilidad del sistema
- Integridad de datos
- Exposición de seguridad
- Degradación de rendimiento

**Impacto de Negocio:**
- Número de usuarios afectados
- Funcionalidad de negocio impactada
- Riesgo de compliance regulatorio
- Impacto en revenue (si es cuantificable)

### 4. Documentación y Evidencia

**Principio Fundamental:**
Todo hallazgo debe estar documentado con evidencia objetiva y reproducible. La documentación sirve múltiples propósitos:
- Facilita la resolución eficiente del defecto
- Proporciona evidencia para auditorías
- Protege profesionalmente al analista de QA
- Permite análisis de tendencias y métricas de calidad

---

## Metodología de Testing

### Testing Más Allá del Happy Path

**Definición de Happy Path:**
El happy path es el escenario ideal donde el usuario proporciona entradas válidas y el sistema responde correctamente. Este es solo el punto de partida del testing.

**Testing Comprehensivo Requiere:**

**1. Testing Positivo (Happy Path)**
- Validar entradas correctas
- Verificar salidas esperadas
- Confirmar transiciones de estado
- Validar persistencia de datos

**2. Testing Negativo**
- Probar entradas inválidas
- Verificar manejo de errores
- Validar mensajes de error
- Confirmar que el sistema rechaza entradas incorrectas apropiadamente

**3. Testing de Casos Límite (Boundary Testing)**
- Valores mínimos y máximos
- Campos vacíos
- Caracteres especiales
- Límites de longitud de strings
- Valores fuera de rango

**4. Testing de Integración**
- Interacciones entre componentes
- Flujos de datos entre módulos
- Manejo de estados compartidos
- Sincronización de operaciones

### Ejemplo Práctico: Testing de Login

**Test Case Asignado:** "Verificar funcionalidad de login"

**Approach Inadecuado:**
```
1. Ingresar credenciales válidas
2. Verificar que login funciona
3. Marcar como PASSED
```

**Approach Profesional:**

**Testing Funcional:**
```
1. Login con credenciales válidas → Verificar acceso exitoso
2. Login con usuario inexistente → Verificar mensaje de error apropiado
3. Login con contraseña incorrecta → Verificar mensaje de error genérico
4. Login con campos vacíos → Verificar validación de campos requeridos
5. Login con usuario válido pero deshabilitado → Verificar acceso denegado
6. Logout → Verificar limpieza de sesión
7. Navegación con botón back después de logout → Verificar sesión cerrada
```

**Testing de Seguridad:**
```
8. Inyección SQL: username = "admin' OR '1'='1' --" → Verificar protección
9. XSS: username = "<script>alert('XSS')</script>" → Verificar sanitización
10. Contraseña visible → Verificar campo type="password"
11. Intentos de login fallidos → Verificar límite de reintentos
12. Fuerza bruta → Verificar implementación de rate limiting
```

**Testing de Usabilidad:**
```
13. Mensaje de error → Verificar claridad sin revelar información sensible
14. Link "Forgot Password" → Verificar funcionalidad
15. Checkbox "Remember Me" → Verificar persistencia de sesión
16. Enter key en form → Verificar submit con teclado
17. Tab navigation → Verificar orden lógico de focus
```

**Testing de Accesibilidad:**
```
18. Screen reader → Verificar anuncios de ARIA labels
19. Contraste de texto → Verificar ratio mínimo 4.5:1
20. Navegación por teclado completa → Verificar sin requerir mouse
21. Identificación de errores → Verificar mensajes accesibles
```

**Testing de Performance:**
```
22. Tiempo de respuesta → Verificar < 200ms para validación
23. Comportamiento con red lenta → Verificar feedback visual
24. Múltiples sesiones simultáneas → Verificar manejo de carga
```

**Resultado del Testing Comprehensivo:**
- Test case original: 1 verificación
- Testing profesional: 24+ verificaciones
- Defectos potencialmente descubiertos: Múltiples vulnerabilidades, problemas de usabilidad, violaciones de accesibilidad

Este es el nivel de rigor esperado en testing profesional de QA.

---

## Estructura del Reporte de Defectos

### Template Estándar

```markdown
## [COMPONENTE] Título Técnico del Defecto

**Issue ID:** [ID del sistema de tracking]
**Reporter:** Andrea [Apellido]
**Fecha de Reporte:** [YYYY-MM-DD HH:MM UTC]
**Severidad:** Critical | High | Medium | Low
**Prioridad:** P0 | P1 | P2 | P3
**Tipo:** Defecto Funcional | Performance | Seguridad | Accesibilidad | UI/UX

---

### Detalles del Ambiente

- **Versión de Aplicación:** [build number o commit hash]
- **Navegador:** [nombre versión completa]
  Ejemplo: Chrome 120.0.6099.109
- **Sistema Operativo:** [OS y versión]
  Ejemplo: Windows 11 22H2 Build 22621.2715
- **Resolución de Pantalla:** [ancho x alto]
- **Tipo de Dispositivo:** Desktop | Tablet | Mobile
- **Rol de Usuario:** [Admin | Usuario Estándar | Invitado]
- **Ambiente de Testing:** [Dev | Staging | Pre-Producción]

---

### Descripción del Problema

**Comportamiento Esperado:**
[Qué debería ocurrir según documentación de requisitos]

**Comportamiento Actual:**
[Qué ocurre realmente - descripción objetiva sin interpretaciones]

**Desviación:**
[Diferencia específica entre esperado y actual]

---

### Pasos para Reproducir

**Precondiciones:**
- [Estado inicial requerido]
- [Datos de prueba necesarios]
- [Configuración específica]

**Pasos:**
1. [Acción precisa con valores específicos]
2. [Incluir datos ingresados exactamente]
3. [Botones clickeados, opciones seleccionadas]
4. [Resultado observado]

**Reproducibilidad:**
- CONSISTENTE: Ocurre 100% de las veces
- INTERMITENTE: Ocurre de manera irregular
- ESPECÍFICO AL AMBIENTE: Solo en ciertas configuraciones

**Resultado Actual:**
[Lo que sucede al seguir los pasos]

**Resultado Esperado:**
[Lo que debería suceder]

---

### Evidencia

**Capturas de Pantalla:**
- Nombrar archivos: `[COMPONENTE]_[DEFECTO]_[FECHA].png`
- Anotar áreas relevantes
- Incluir contexto suficiente

**Logs de Consola:**
```
[Pegar output relevante de la consola del navegador]
[Incluir timestamp si está disponible]
```

**Actividad de Red:**
- Adjuntar archivo HAR si es relevante
- Documentar requests fallidos
- Notar timeouts o errores de respuesta

**Evidencia de Base de Datos:** (si aplica y está autorizado)
```sql
-- Query que muestra el estado incorrecto
SELECT * FROM tabla WHERE condicion;
```

---

### Análisis de Impacto

**Impacto a Usuarios:**
- Usuarios Afectados: [porcentaje o cantidad]
- Frecuencia: [siempre | frecuente | intermitente | raro]
- Función de Negocio: [qué proceso está bloqueado/afectado]
- Riesgo a Datos: [ninguno | bajo | medio | alto]

**Impacto a Negocio:**
- Impacto en Revenue: [si es cuantificable]
- Riesgo de Compliance: [implicaciones regulatorias/legales]
- Riesgo Reputacional: [impacto visible al usuario]

**Impacto Técnico:**
- Estabilidad del Sistema: [causa crashes/cuelgues]
- Performance: [métricas de degradación]
- Seguridad: [tipo de vulnerabilidad si aplica]

---

### Cumplimiento de Estándares

**Estándares Violados:** (si aplica)
- WCAG 2.1: [criterio específico]
  Ejemplo: 1.1.1 Non-text Content
- OWASP: [vulnerabilidad específica]
  Ejemplo: A03:2021 Injection
- Performance: [métrica específica]
  Ejemplo: Page Load Time > 3s (actual: 8.2s)
- Design System: [guideline específico]

**Impacto Regulatorio:** (si aplica)
- ADA Section 508
- GDPR
- HIPAA
- PCI-DSS

---

### Workaround

**Disponible:** Sí | No

[Si existe, documentar procedimiento detallado del workaround]

---

### Contexto Adicional

- Primera Observación: [fecha/build]
- Issues Relacionados: [IDs de defectos relacionados]
- Regresión: [sí/no - si funcionaba en versión previa]
- Cambios Recientes: [deployments/updates relacionados]

---

### Adjuntos

- [ ] Capturas de pantalla
- [ ] Grabación de pantalla
- [ ] Logs de consola
- [ ] Trace de red (archivo HAR)
- [ ] Logs de aplicación
- [ ] Archivo de datos de prueba
```

---

## Criterios de Cobertura de Testing

### Matriz de Cobertura para Cada Feature

| Categoría | Criterios de Verificación | Estándar de Industria |
|-----------|--------------------------|----------------------|
| **Funcional** | Happy path, casos negativos, edge cases, integración | ISTQB Foundation |
| **Seguridad** | OWASP Top 10, input validation, autenticación, autorización | OWASP ASVS Level 2 |
| **Accesibilidad** | WCAG 2.1 Level AA completo, keyboard navigation, screen readers | WCAG 2.1, Section 508 |
| **Performance** | Page load < 3s, TTI < 5s, API response < 200ms | Core Web Vitals |
| **Usabilidad** | Intuitividad, consistencia, claridad de mensajes | Nielsen Heuristics |
| **Responsive** | Desktop, tablet, mobile, orientaciones | Mobile-first design |

### Checklist Técnico por Feature

**Funcionalidad:**
- [ ] Caso ideal funciona correctamente
- [ ] Datos inválidos son rechazados apropiadamente
- [ ] Campos vacíos son validados
- [ ] Caracteres especiales son manejados
- [ ] Límites de longitud son respetados
- [ ] Mensajes de error son claros y específicos
- [ ] Estado de datos es persistido correctamente

**Seguridad:**
- [ ] Input está sanitizado (no acepta SQL injection)
- [ ] Output está encoded (no permite XSS)
- [ ] Autenticación es robusta
- [ ] Autorización es validada
- [ ] Contraseñas están hasheadas
- [ ] Sesiones tienen timeout
- [ ] Rate limiting está implementado
- [ ] HTTPS es forzado

**Accesibilidad:**
- [ ] Navegación completa por teclado (Tab, Enter, Escape)
- [ ] Contraste de color cumple ratio mínimo 4.5:1
- [ ] Imágenes tienen alt text descriptivo
- [ ] Formularios tienen labels asociados
- [ ] Errores son anunciados por screen readers
- [ ] Focus indicators son visibles
- [ ] Orden de tab es lógico
- [ ] ARIA labels están implementados correctamente

**Performance:**
- [ ] Page load time < 3 segundos
- [ ] First Contentful Paint < 1.8 segundos
- [ ] Time to Interactive < 5 segundos
- [ ] API response time < 200ms (P95)
- [ ] No memory leaks observados
- [ ] Network requests están optimizados

**Usabilidad:**
- [ ] Flujo es intuitivo
- [ ] Labels son claros y descriptivos
- [ ] Feedback visual es inmediato
- [ ] Consistencia de diseño se mantiene
- [ ] Mensajes son en lenguaje del usuario
- [ ] Ayuda contextual disponible donde se necesita

---

## Clasificación de Severidad y Prioridad

### Severidad (Technical Impact)

**CRITICAL:**
- Crash de aplicación
- Pérdida de datos
- Breach de seguridad
- Funcionalidad core completamente rota
- Violación de compliance legal

*Ejemplo:* SQL Injection permitiendo acceso no autorizado a datos

**HIGH:**
- Feature major no funcional
- Impacto significativo a usuarios
- Workaround difícil o no práctico
- Degradación de performance > 50%
- Violación de estándares importantes

*Ejemplo:* Checkout process roto sin alternativa

**MEDIUM:**
- Feature parcialmente funcional
- Impacto moderado
- Workaround razonable existe
- Violación de estándares no crítica

*Ejemplo:* Filtros de búsqueda no funcionan correctamente

**LOW:**
- Issues cosméticos
- Inconveniente menor
- Workaround fácil
- Mejoras sugeridas

*Ejemplo:* Typo en texto de UI

### Prioridad (Business Impact)

**P0 (Inmediato):**
- Bloquea release
- Impacto crítico al negocio
- Debe corregirse antes de deploy

**P1 (Alto):**
- Debe corregirse en sprint actual
- Impacto significativo a usuarios
- Afecta workflows clave

**P2 (Medio):**
- Corregir en 1-2 sprints
- Afecta features secundarios
- Workaround está documentado

**P3 (Bajo):**
- Corregir cuando sea conveniente
- Impacto mínimo
- Enhancement/mejora

---

## Ejemplos de Casos Reales

### Caso 1: Vulnerabilidad de Seguridad - Inyección SQL

**Contexto de Descubrimiento:**
Durante testing de la funcionalidad de login, además de verificar el happy path, se realizaron pruebas de seguridad con payloads maliciosos según OWASP Testing Guide.

**Título:** [Autenticación] Inyección SQL en Formulario de Login Permite Bypass de Autenticación

**Severidad:** CRITICAL | **Prioridad:** P0

**Descripción del Problema:**
El formulario de login no sanitiza correctamente el input del campo username, permitiendo la ejecución de comandos SQL arbitrarios que resultan en bypass completo de autenticación.

**Pasos para Reproducir:**
```
Precondiciones: Ninguna

Pasos:
1. Navegar a /login
2. En campo username ingresar: admin' OR '1'='1' --
3. En campo password ingresar: cualquiervalor
4. Click en botón "Iniciar Sesión"

Resultado Actual:
- Usuario autenticado exitosamente
- Redirigido a /dashboard
- Session cookie generado: session_id=abc123...
- Acceso completo sin credenciales válidas

Resultado Esperado:
- Login rechazado
- Mensaje de error: "Credenciales inválidas"
- Sin generación de session
- Input sanitizado o parametrizado
```

**Evidencia Técnica:**
```
Request:
POST /api/login
username=admin' OR '1'='1' --&password=cualquiervalor

Response:
HTTP/1.1 302 Found
Location: /dashboard
Set-Cookie: session_id=abc123def456...
```

**Análisis de Impacto:**
- **Usuarios Afectados:** 100% (todos los usuarios del sistema)
- **Impacto de Seguridad:** CRÍTICO - Bypass completo de autenticación
- **Acceso No Autorizado:** Total acceso a datos y funcionalidad
- **Compliance:** Violación de OWASP, PCI-DSS si aplica
- **Riesgo Legal:** Alto - breach de seguridad reportable

**Estándares Violados:**
- OWASP Top 10 2021: A03 Injection
- CWE-89: SQL Injection
- OWASP ASVS: V5.3.4 SQL Injection Prevention

**Recomendación Técnica:**
```python
# Implementación Incorrecta (Actual):
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

# Implementación Correcta (Recomendada):
query = "SELECT * FROM users WHERE username=? AND password=?"
cursor.execute(query, (username, hashed_password))
```

Utilizar prepared statements o un ORM que maneje sanitización automáticamente. Nunca concatenar input de usuario directamente en queries SQL.

---

### Caso 2: Violación de Accesibilidad WCAG 2.1

**Contexto de Descubrimiento:**
Durante testing de accesibilidad con screen reader (NVDA), se identificó que las imágenes de productos no proporcionan información textual alternativa.

**Título:** [Catálogo de Productos] Imágenes sin Texto Alternativo - Violación WCAG 2.1 Level A

**Severidad:** HIGH | **Prioridad:** P1

**Descripción del Problema:**
Todas las imágenes de productos en el catálogo carecen del atributo alt, impidiendo que usuarios de screen readers comprendan el contenido visual y violando WCAG 2.1 Success Criterion 1.1.1.

**Pasos para Reproducir:**
```
Precondiciones: Screen reader activo (NVDA, JAWS, o similar)

Pasos:
1. Navegar a /products
2. Activar screen reader
3. Navegar a través de productos usando teclas de flecha
4. Observar anuncios del screen reader

Resultado Actual:
- Screen reader anuncia: "Gráfico" o "Imagen" sin contexto
- Sin información sobre qué producto es
- Usuario no puede identificar productos visualmente

Resultado Esperado:
- Screen reader anuncia: "Samsung Galaxy S23 smartphone en Negro Fantasma, 256GB"
- Usuario comprende qué producto está viendo
```

**Evidencia Técnica:**
```html
<!-- Estado Actual (Incorrecto): -->
<img src="/images/samsung-galaxy-s23.jpg"
     class="product-image">

<!-- Estado Esperado (Correcto): -->
<img src="/images/samsung-galaxy-s23.jpg"
     alt="Samsung Galaxy S23 smartphone en Negro Fantasma, 256GB, pantalla 6.1 pulgadas"
     class="product-image">
```

**Análisis de Impacto:**
- **Usuarios Afectados:** 8-10% de usuarios (estimado de usuarios con discapacidad visual)
- **Compliance:** Violación de ADA, Section 508
- **Riesgo Legal:** Alto - demandas por accesibilidad son comunes
- **SEO:** Impacto negativo - motores de búsqueda no pueden indexar imágenes
- **Business:** Exclusión de segmento significativo de usuarios

**Estándares Violados:**
- WCAG 2.1 Level A: Success Criterion 1.1.1 (Non-text Content)
- Section 508: § 1194.22(a)
- EN 301 549: 9.1.1.1
- Americans with Disabilities Act (ADA)

**Alcance del Defecto:**
- 47 imágenes de productos en catálogo
- 12 imágenes de categorías
- 8 imágenes en página de inicio
- **Total:** 67 imágenes requieren remediación

**Recomendación Técnica:**
Implementar alt text descriptivo siguiendo formato:
```
[Marca] [Modelo] [Característica Visual Clave], [Especificación Relevante]

Ejemplos:
- "iPhone 15 Pro Max en Titanio Azul, 512GB, sistema de cámara triple"
- "MacBook Pro 16 pulgadas en Gris Espacial, chip M3 Max"
- "Samsung QLED TV 65 pulgadas, 4K, marco ultra delgado"
```

---

### Caso 3: Componente Sin Funcionalidad

**Contexto de Descubrimiento:**
Durante testing exploratorio del carrito de compras, se identificó un botón que no tiene funcionalidad implementada.

**Título:** [Carrito] Botón "Guardar para Después" No Tiene Funcionalidad Implementada

**Severidad:** MEDIUM | **Prioridad:** P2

**Descripción del Problema:**
El botón "Guardar para Después" en la página del carrito aparenta ser funcional pero no ejecuta ninguna acción al ser clickeado. Sin feedback visual, sin funcionalidad backend, sin mensaje de error.

**Pasos para Reproducir:**
```
Precondiciones:
- Usuario autenticado
- Al menos un producto en el carrito

Pasos:
1. Agregar producto al carrito
2. Navegar a /cart
3. Localizar botón "Guardar para Después" bajo cada producto
4. Click en botón "Guardar para Después"
5. Observar resultado

Resultado Actual:
- No hay feedback visual (sin loading state)
- Producto permanece en carrito
- No hay mensaje de éxito o error
- Inspección de Network tab: sin request HTTP
- Sin cambio en estado de UI

Resultado Esperado:
Opción A (Si está implementado): Producto movido a lista "Guardados"
Opción B (Si no está implementado): Botón deshabilitado con tooltip
Opción C: Botón no debería existir hasta implementación
```

**Evidencia Técnica:**
```html
<button class="btn-save-later" onclick="saveLater(123)">
  Guardar para Después
</button>

<!-- JavaScript (función vacía): -->
<script>
function saveLater(productId) {
  // TODO: Implementar funcionalidad
}
</script>
```

**Análisis de Impacto:**
- **Usuarios Afectados:** 100% de usuarios que usan carrito
- **Impacto UX:** Confusión - usuarios esperan funcionalidad
- **Credibilidad:** Percepción de software incompleto o roto
- **Support:** Potencial incremento en tickets de soporte

**Preguntas para Equipo de Desarrollo:**
1. ¿Esta funcionalidad está planificada para implementación futura?
2. ¿Debería el botón estar deshabilitado hasta implementación?
3. ¿Debería removerse el botón completamente?
4. ¿Existe endpoint backend para esta funcionalidad?

**Recomendaciones:**
```
Opción 1 (Preferida): Implementar funcionalidad completa
Opción 2: Deshabilitar botón con tooltip explicativo
  <button disabled title="Próximamente">Guardar para Después</button>
Opción 3: Remover botón hasta implementación completa
```

**Justificación del Reporte:**
Aunque este no es un "bug" en sentido técnico, es un problema de calidad que afecta UX. Como analista de QA, es responsabilidad documentar inconsistencias entre UI y funcionalidad, especialmente cuando pueden confundir usuarios o generar tickets de soporte.

---

## Referencias y Estándares

### Estándares de Testing
- **ISTQB Foundation Level:** International Software Testing Qualifications Board
- **IEEE 829-2008:** Standard for Software Test Documentation
- **ISO/IEC 25010:** Systems and software Quality Requirements and Evaluation (SQuaRE)

### Estándares de Accesibilidad
- **WCAG 2.1:** Web Content Accessibility Guidelines (W3C)
- **Section 508:** Rehabilitation Act (US Federal)
- **EN 301 549:** Accessibility requirements (European)
- **ADA:** Americans with Disabilities Act

### Estándares de Seguridad
- **OWASP Top 10:** Top 10 Web Application Security Risks
- **OWASP ASVS:** Application Security Verification Standard
- **CWE Top 25:** Common Weakness Enumeration
- **SANS Top 25:** Most Dangerous Software Errors

### Estándares de Performance
- **Core Web Vitals:** Google's web performance metrics
- **Web Performance Working Group:** W3C standards
- **HTTP Archive:** Web performance benchmarks

### Recursos Adicionales
- ISTQB Glossary: https://glossary.istqb.org/
- WCAG Quick Reference: https://www.w3.org/WAI/WCAG21/quickref/
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/

---

## Notas Importantes sobre Responsabilidad Profesional

### Due Diligence Profesional

La documentación exhaustiva de defectos no es solo una best practice, es una responsabilidad profesional que:

1. **Facilita Resolución Eficiente**
   - Desarrolladores pueden reproducir y corregir issues rápidamente
   - Se minimiza comunicación back-and-forth
   - Se reduce time-to-resolution

2. **Proporciona Evidencia**
   - Protege profesionalmente al analista de QA
   - Demuestra cobertura de testing comprehensiva
   - Sirve como evidencia en auditorías

3. **Mejora Calidad del Producto**
   - Issues bien documentados se corrigen correctamente
   - Se previenen regresiones
   - Se mantiene knowledge base de defectos

4. **Protege al Negocio**
   - Se identifican riesgos de compliance antes de producción
   - Se previenen problemas legales (accesibilidad, seguridad)
   - Se mantiene reputación del producto

### Accountability Profesional

Como analista de QA, su accountability incluye:
- Cobertura thoroughness de testing
- Precisión en documentación
- Oportunidad en reporte
- Verificación de resolución

La pregunta clave no es "¿Este issue está en mi test case?" sino "¿Este issue afecta la calidad del software y la experiencia del usuario?"

Si la respuesta es afirmativa, debe ser reportado.

---

*Versión del Documento: 2.0*
*Última Actualización: 09/12/2024*
*Compliance: ISTQB Foundation Level, IEEE 829, ISO/IEC 25010*
*Preparado específicamente para: Andrea - QA Analyst*
