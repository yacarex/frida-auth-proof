# Harness proveedor-neutral — plan, no implementación

CONSUMER-AUTH-INTEROP-01 v1. Ningún archivo ejecutable, dependencia, fixture o workflow nuevo.

## Componentes y fronteras

1. Manifest inmutable de ensayo: profileVersion/commit, modo OAuth por client, issuer, client IDs/audiences, callbacks, configuración, TTL, SDK/toolchain/lock, fecha/plan/entitlements, scopes autorizados y recursos sintéticos exactos.
2. Driver estándar OAuth/OIDC mantenido: construcción de solicitudes/PKCE/token validation mediante librería; browser automation externo para autorización. No crypto, OAuth server, refresh broker o wrappers de reparación.
3. Adapter administrativo mínimo por proveedor: traducir setup/readback/list/revoke/export/delete a APIs soportadas; sin transformar respuestas de token ni implementar familias propias. Declara missing capabilities; jamás altera oráculos.
4. Recorder de transporte con esquema allowlist: requests/responses salientes reales, correlación de intentos, timestamps; sanitiza antes de persistir. Separar emisión AS, aceptación SDK, aceptación Frida y observación física.
5. Driver Frida aislado: sólo en un futuro proof autorizado conecta contratos User/AuthBinding/fence a fixtures Worker/D1. No integra el IdP en producción ni concede permisos por conveniencia.
6. Oráculos K1–K6 y N-* independientes de adapters; plan de fallos, concurrencia, export y cleanup versionado. Reporting nunca convierte assertion esperada en resultado.

No usar fixtures que devuelvan “verified=true” para acreditar proveedor. Doubles sirven exclusivamente para fallos locales identificados (clock local, outage, fence), con resultados etiquetados. Los tests de wire negativos usan SDK con mecanismos de transporte soportados; si éste impide construir el negativo, separar solicitud HTTP estándar de test y dejarlo explícito, sin reimplementar flujo/crypto productivo.

## Manifest conceptual obligatorio

Campos: profile_id, profile_commit, mode_by_client, issuer, discovery_snapshot_hash, allowed_endpoints, native_client_id, bff_client_id, admin_identity_client_id si autorizado, resource_audiences, exact_redirects, allowed_algorithms, clock_skew, TTL_policy, SDK_versions, adapter_commit, scopes_granted, entitlement_snapshot, synthetic_resource_allowlist, restore_snapshot, cleanup_plan, evidence_policy.

No secretos en manifest. Custodia efímera/segura separada; Native siempre sin client secret. Scopes no concedidos producen capability missing, nunca autoelevación. Alterar manifest durante ejecución invalida la comparación: registrar nuevo run ligado, no sobrescribir.

## Registro de prueba conceptual

Cada case conserva:
- requirement_id y knockout_id, severidad MUST/SHOULD/UX;
- owner AS/client/Frida/platform/operations;
- profile_mode y config hash;
- precondiciones comprobadas, control positivo, request correlation IDs;
- estímulo único, campos públicos enviados, timestamps/clock source;
- HTTP status/error, token_issued y token_validation_result por separado;
- session_created, binding_changed, family_effect, domain_side_effect;
- expected oracle fijado antes, actual observable y resultado;
- artifact/source hashes, captura directa vs reconstrucción;
- límites/UNKNOWN, fixtures creados, restauración/ausencia verificada.

No almacenar códigos, verifiers, refresh/access/ID tokens, cookies, contraseñas, secretos, enlaces de tickets ni PII. IDs sintéticos pseudónimos y digests salados efímeros pueden correlacionar sin publicar credenciales. A/B de test son públicos, permitidos. Export de estado público sintético cifrado/restringido según sensibilidad; nunca clave privada de autenticador.

## Plan de ejecución futuro

**Preflight:** verificar autorización, main intacto, árbol/proof aislado, audit sólo de dependencias del proof, permisos agregados completos y alcance de conexiones. Capturar config antes de cualquier cambio y restauración exacta aprobada. No cuentas reales, shared connections ni defaults ajenos. Leer plan/coste, no contratar.

**Knockouts:** primero documental K6/permisos y profile; luego K1/K2, K3/K4, K5 y export sintético K6. Pocas familias/codes y rate budget fijado; detener una rama al primer FAIL sustantivo, cleanup en finally y recuperación si falla. No ejecutar pruebas posteriores para compensar.

**Matriz completa:** sólo tras autorización y supervivencia; requirements N-* con runtime real Worker/D1, correo sintético autorizado, dispositivos físicos cuando autorizados. Android browser simulado no completa physical gate. TTL largo requiere método soportado o ensayo programado expresamente autorizado; no esperas ocultas ni schedule creado aquí.

**Reporte:** immutable artifacts + commit/run identity + matriz por requisito. Diferenciar histórico/acreditado actual/NOT_RUN. Documento final de candidatura y viabilidad comercial independientes. Nada de un único “todoPASS” mezclando árboles/planes.

## Concurrencia y atomicidad local

AS controla consumo de code y refresh; se observa desde clientes independientes con barrera. El harness no serializa la prueba de carrera ni introduce grace artificial. El single-flight productivo es una política aparte.

Frida local:
- Intento NEW → IN_FLIGHT por CAS; callback repetido no genera segunda sesión.
- Intercambio remoto exitoso no es commit local: validar tokens primero.
- Commit local único: binding explícito/ownership, epochs, consumo de intento, sesión/familia y evento; todas las guardas en misma frontera.
- Fallo después del exchange/antes de commit: no autorización local; compensación upstream soportada/outbox, sin devolver token a usuario. Code no se puede volver a gastar como retry.
- Resultado local committed con respuesta perdida: entrega idempotente del estado de la misma sesión a la misma instancia autenticada del intento; no reemisión/replay de refresh ni nueva sesión. Si no puede recuperarse con seguridad, revocar y pedir login.
- Revoke vs write: orden de commit en store de dominio determina ganador; zero-row mismatch aborta todo. D1 batch no implica callback transaccional ni transacción distribuida.
- Simular interrupción antes/después de cada frontera, store outage, callback reorder, replay, epoch change, restore antiguo. Tombstones/epoch no retroceden.

Este diseño no implementa el fence ni cambia 0022. Su futura evolución requiere slice separado con pruebas; un mock de commit no acredita D1.

## Exit drill y cleanup

Registrar recursos creados por este run, no descubrir usuarios generales. Exportar cuentas sintéticas y binding map; verificar conteos/IDs, documentar campos perdidos, ensayar restore si soportado o reenrollment explícito en entorno autorizado. Revocar sesiones, preservar User IDs y tombstones. Nunca mover bearer activo al destino ni enlazar por email.

Cleanup: revocar familias y borrar usuarios/credenciales/conexión/client sólo si fueron creados por run y autorización permite; restaurar únicamente configuración propia cambiada, con compare de snapshot para no pisar cambios ajenos. Readback de ausencia/restauración, errores/429 y retry acotado. Cleanup pendiente bloquea cierre operativo, no borra resultado de seguridad. Artefactos públicos sanitizados, secretos destruidos; no asumir que delete-user invalida instantáneamente JWT ya emitido.

## Qué no es adaptable

El adapter no puede:
- cambiar modo OAuth tras observar A!=B;
- aceptar state/nonce incorrectos o reemplazar callback enviado;
- renovar familia propia para ocultar reuse del motor;
- usar grace>0, grant-wide revoke para simular aislamiento o auto-link por email;
- convertir User/sub en equivalentes;
- atribuir UV Admin al proveedor;
- fabricar email verificado, token validation o PASS por pantalla;
- omitir negativos por limitaciones de SDK sin registrar bloqueo;
- instalar fork/override para corregir contrato.

## Alcance público

Plan congelado de referencia; implementaciones nuevas deben distinguir ejecución real de diseño. El primer paquete público prepara K1; K2–K6 no pueden ejecutarse antes de sus gates precedentes.

