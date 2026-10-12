# Knockout profile — Consumer Auth v1

Contrato congelado antes de seleccionar candidato. No ejecución en esta entrega.
Lectura: MUST es condición de aceptación; SHOULD requiere justificación aprobada; UX PREFERENCE no elimina candidatos. Los K-* siguientes son MUST. No ranking ni nuevo proveedor.

## Preflight documental obligatorio

Fijar manifest de perfil/client/versión/configuración y totalidad de scopes/entitlements necesarios para K1–K6 y matriz N01–N54. Fuentes primarias o contrato soportado; si falta garantía de propiedad crítica, UNKNOWN/BLOCKED, no PASS por marketing. Si contradice un MUST, FAIL sin profundizar integración. No crear tenant/prueba por la aprobación de este documento.

SaaS debe identificar snapshot de configuración, región, plan/trial y fecha; versión de backend puede ser UNKNOWN, registrada. SDK/harness/lock sí con versiones/hash exactos. Recuperar evidencia previa sin atribuirla a un candidato nuevo.

## Seis knockouts

| Gate | IDs | Secuencia mínima futura | Oráculo / stop |
|---|---|---|---|
| K1 OAuth code/redirect binding | N01–N04,N06–N07 | Perfil fijado; control válido con A. Registro: B no registrado falla en autorización. O20: codes independientes, token con B registrado alternativo, B no registrado y sin redirect; O21: token sin campo, callback local distinto de A, code inyectado de otro intento/client y verifier propio. Replay y expiry servidor | O20 nunca emite por A!=B/ausencia. O21 no exige campo ausente: AS aplica client/PKCE/code y cliente rechaza callback equivocado. Replay no emite; expirado no emite. FAIL detiene |
| K2 Public Native / PKCE | N01,N05,N08–N12,N36 | Cliente Native público sin secret; S256 control; wrong/missing verifier, plain downgrade, wrong client conocido separado, code del otro client. Claims cruzados y algoritmo no permitido | Sin secret ni wrappers. Intercambio inválido no emite; ID/access inválidos no producen sesión local. Rechazo sólo en cliente no prueba control AS |
| K3 Rotation / reuse / concurrencia | N13–N16 | Familia A; A0→A1→A2, reuse A0 y A1; casos independientes inmediato y tardío con token original aún dentro de vida absoluta. Dos peticiones A0 simultáneas; respuesta perdida. Probar todos los descendientes registrados tras detección | Grace0, a lo sumo una emisión sucesora, familia comprometida deja de refrescar incluidos descendientes/ganador. No replay del par ni ampliación de grace; cualquier descendiente superviviente ⇒ FAIL |
| K4 Family/device isolation / revocation | N15,N17–N23 | Mismo User + mismo client + misma audience, logins A/B realmente independientes; reuse A seguido de refresh B. Casos independientes revoke-one, family y all. Access todavía vigente contra fence revocado; SSO residual | Reuse/revokeA conserva B; all invalida ambas. Familia identificable y revocable por contrato soportado. JWT vigente no autoriza tras commit fence. Grant-wide involuntario ⇒ FAIL |
| K5 User/AuthBinding / no email-link | N24–N33,N44 | User Frida X existente y sub distinto; binding explícito. Dos subjects con email igual/verificado; login por cada método habilitado; conflicto de ownership, linking sin prueba legacy, recovery/email change, callback repetido | X/IDs/historia intactos; ningún merge/link por email; ningún Provider/ownership/admission/grant nuevo. Consumer no Admin. Colisión/recovery ambiguo deniegan. Auto-merge impuesto ⇒ FAIL |
| K6 Exit / acceso operativo | N45–N52 | Contrato export esencial/IDs/config, sample sintético cuando proof autorizado; plan de continuidad RP/reenrollment; revocación/cleanup API disponibles post-trial; coste/privacidad documentados | No exigir portabilidad inexistente de privadas ni sesiones. Salida viable sin perder User obligatoria. Incapacidad demostrada ⇒ FAIL. Falta de entitlement/cotización/evidencia ⇒ BLOCKED; no aceptación comercial por trial |

No se ejecutan K3/K4 sobre Auth0: su Gate1 histórico se conserva acotado y proveedor rechazado. Gate2 Auth0 no se repite ni forma parte de estos knockouts. Tampoco se repiten Better Auth, ZITADEL o Market Screen.

## Precisiones del oráculo

- Cada negativo usa code/familia nueva salvo replay intencional. No agotar un code con otro error y atribuir rechazo posterior al campo equivocado.
- Capturar autorización y token request en el transporte real, allowlist de campos; no sólo URL reconstruida. A/B y presencia del verifier pueden registrarse sin secreto. El JWT resultante se verifica en memoria por SDK independiente; no se publica token.
- Un HTTP200 de token endpoint con tokens emitidos es relevante aun si el SDK los rechaza después: registrar ambos niveles. Un timeout/429/5xx no acredita rechazo normativo.
- Code expiry requiere reloj real del servidor o mecanismo de test soportado. Adelantar reloj de verificador local sólo prueba exp local, nunca expiry de code/refresh upstream.
- Tardío: fixture propone 3 rotaciones, reuse inmediato y ≥60s después del consumo (parámetro de observación, no permiso de grace). Para TTL 7d/30d se necesita evidencia de enforcement soportada y prueba temporal o reloj oficial; no rebajar cifras sólo para terminar antes. Config readback ≠ expiración runtime. Cualquier límite no cubierto queda NOT_RUN y gate operativo pendiente.
- Concurrencia: barrera de envío y tiempos de llegada/respuesta medidos; repetir sólo hasta acreditar interleaving requerido, sin retries que escondan el perdedor. Tras respuesta de reuse terminada se prueban descendientes conocidos; operaciones ya emitidas se listan.
- Cookies SSO compartidas no invalidan por sí mismas dos familias: demostrar IDs/generaciones independientes y los controles válidos A/B antes del negativo. Label de dispositivo no es esa demostración.
- Export de claves públicas no implica restore válido. K6 puede sobrevivir con reenrollment seguro acreditable; antes de rollout se ensaya restore o ruta de reenrolamiento completa.

## Estados y decisión

PASS DOCUMENTAL: contrato soportado, no ejecución.
PASS RUNTIME: observación del sistema bajo versión/configuración exacta, con evidencia suficiente.
FAIL: contradicción demostrada; parar, limpiar fixtures autorizados, conservar prueba.
UNKNOWN: evidencia insuficiente. BLOCKED: impedimento externo preciso (permiso, plan, infraestructura).
NOT_RUN: no ejecutado, incluido lo posterior a un stop.
REQUIRES FRIDA FENCE: asignación de responsabilidad, no resultado ni waiver.

Un MUST en FAIL elimina. Un MUST UNKNOWN/BLOCKED no permite aceptación ni prueba completa sin resolver preflight; no prueba ausencia universal de feature. Todos los K-* PASS sólo permiten solicitar siguiente proof, no release ni aceptación final. Matriz completa requiere todos los MUST, decisiones previas sobre SHOULD y gate comercial separado. Cambiar MUST implica nueva versión y Dirección antes de reensayar; nunca adaptar a posteriori.

## Fuera del knockout reducido, obligatorio antes de aceptación/rollout

Web BFF/CSRF/fixation; JWKS rotation/outages; TTL temporal completo; callbacks out-of-order/restarts; passkeys múltiples y revocación; correo/recovery reales sintéticos; Worker/D1 fail-closed; Android físico con firma/App Links; export/restore y privacidad; cleanup verificado; post-trial coste aprobado. No sobredimensionar un primer knockout con navegación UX; no omitir estos gates del proof completo.

