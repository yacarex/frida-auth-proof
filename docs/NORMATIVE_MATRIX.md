# Matriz normativa Consumer — v1

Parte de CONSUMER-AUTH-INTEROP-01. Cada ID es estable y debe aparecer en el informe del futuro candidato. Toda nueva ejecución está NOT_RUN. Fuentes primarias al final. P = política Frida; E = estándar; C = composición de ambos.

## OAuth/OIDC: perfil por cliente

El manifest fija exactamente issuer, endpoints descubiertos/permitidos, client_id, audience API, redirect canónico, modo O21-D16 u O20-PKCE, algoritmos y versión de SDK. La etiqueta comercial “OAuth 2.1 compliant” no basta. Modo desconocido bloquea el gate; no hay auto-downgrade.

| ID | Nivel / origen | Obligación y oráculo | Responsable |
|---|---|---|---|
| N01 | MUST C S1–S4 | Authorization Code + S256, OIDC scope openid; no implicit, ROPC ni plain. Verifier nuevo por intento mediante SDK mantenido, sin crypto propia | AS y cliente |
| N02 | MUST E S1/S2 | O20-PKCE: autorización incluye A; token incluye exactamente A. Ausente/B diferente se rechaza, aunque B también esté registrado. PKCE correcto no exime | AS |
| N03 | MUST C S3 | O21-D16: autorización usa A registrado; token request omite redirect_uri. Code vinculado a client y challenge; code ajeno con verifier propio, verifier ausente/incorrecto y wrong client fallan. Callback local distinto de A no se procesa | AS + cliente |
| N04 | MUST C | Registrar callbacks HTTPS exactos, sin wildcard/open redirect. Validación contra registro y binding al intento son controles distintos. Si AS soporta clientes 2.0/2.1, fijar modo por client y probar compatibilidad separada | AS |
| N05 | MUST P | Native público sin secret; client_id identifica, no autentica una APK. No requerir secret/public-client disfrazado. Web BFF puede usar credencial confidencial server-only y PKCE | AS + clientes |
| N06 | MUST P | state y nonce independientes, impredecibles, por intento, one-use; state ausente/mismatch/replay falla en callback; nonce del ID token ausente/mismatch falla tras validar firma. Intentos paralelos separados, callback tardío no sustituye intento actual | Cliente/BFF |
| N07 | MUST C S1 | Code one-use y expiry servidor ≤60s (límite Frida, no cifra impuesta por RFC). Replay/concurrencia: no dos intercambios válidos. Intento local ≤10min no extiende code | AS y cliente |
| N08 | MUST C S5 | ID token: firma, issuer exacto, subject, aud del client, exp/iat/nbf aplicable, nonce esperado; no ID token como bearer API. azp si extensión lo usa: validar client según contrato explícito | Cliente/BFF |
| N09 | MUST P | Access API: issuer, audience API, client autorizado mediante claim soportado client_id/azp o introspección, exp/nbf y tipo. Claim azp no universal ni suficiente por nombre; multi-audience sólo allowlist explícita. Token Admin/Consumer cruzado denegado | Frida resource server |
| N10 | MUST C S6 | Algoritmos asimétricos allowlist explícita RS256/ES256 según candidato; rechazar none, HS confusion, alg inesperado, firma inválida, clave/issuer cruzados. No elegir algoritmo por entrada no confiable | SDK/verificador mantenido |
| N11 | MUST P | JWKS HTTPS desde issuer configurado; no jku/x5u arbitrario. kid desconocido permite una recarga acotada, luego deniega. Cache válida y acotada puede validar claves conocidas; cache vencida + outage deniega. Rotación, key removal y emergencia documentadas; rate-limit de recargas | Verificador |
| N12 | MUST P | Tokens opacos sólo con introspección soportada y client/aud/fence verificables. No inventar campos; indisponibilidad sin evidencia vigente falla cerrada | Frida + AS |

N03 no aplica el test ficticio A!=B al campo ausente: el gate equivalente es registro estricto + entrega a A + code/client/PKCE binding + validación del callback. No se exige al AS rechazar un parámetro extra en modo exclusivamente 2.1 si su contrato lo ignora; eso no cambia la obligación N02 para compatibilidad 2.0. Un cliente 2.0 con error no se reclasifica a posteriori. En ambos modos state/nonce son política obligatoria Frida aun si una especificación admite otras defensas.

ID token y access token se verifican por contratos distintos. OAuth 2.1 no sustituye OIDC. No exigir azp universal: OIDC errata set 2 lo trata en extensiones; Frida exige correlación client inequívoca por el mecanismo soportado seleccionado.

## Sesiones, revocación y fence

| ID | Nivel / origen | Contrato |
|---|---|---|
| N13 | MUST P | Access consumidor ≤300s; objetivo300s, skew de validación máximo30s, no extensión de TTL por cache. Refresh idle máximo7d y absoluto máximo30d desde familia original; objetivos7d/30d. Rotación no reinicia absoluto |
| N14 | MUST P, motivado S4 | Rotation cada uso, grace=0. Reuse de cualquier generación consumida invalida toda familia y descendientes, incluido ganador concurrente, antes de completar la respuesta de detección. Reuse inmediato/tardío no devuelve mismo par ni permite descendiente activo |
| N15 | MUST P | Misma persona/client/audience con familias A/B: reuse/revoke-family A no daña B. Nunca confundir grant, cookie SSO, sesión, familia, instalación y dispositivo físico |
| N16 | MUST P | Refresh simultáneo del mismo token: a lo sumo una emisión sucesora; perdedor detecta reuse y sucesor queda inválido. Single-flight cliente evita carreras accidentales, no remedia motor incorrecto. Respuesta perdida ⇒ login fresco; no retry automático de refresh ambiguo |
| N17 | MUST P | Una Session/Family local por login/instalación/audience; mapping upstream verificable a revocación dirigida. Máximo5 familias Consumer activas; elegir revocar una o rechazar sexta, nunca expulsión silenciosa |
| N18 | MUST P | Revoke-one=session: revocar sesión local y su familia upstream asociada, sin tocar B. Revoke-family: toda familia/generaciones. Revoke-all: todas familias del User, incluidos canales legacy/Admin según política ya aprobada. Revocar sólo un RT antiguo no acredita revoke-session |
| N19 | MUST P | Logout local cierra sesión/familia local, limpia cookie/estado y programa revocación upstream. Logout family confirma alcance remoto. Logout SSO es operación adicional con estado propio, no revoca automáticamente todos los tokens |
| N20 | MUST P | Fence local en cada request; User/auth/credential epoch, session/family y permisos actuales. Access aún firmado/vigente no evade revocación. Revoke se linealiza en store de dominio antes de side effect upstream; outbox durable reintenta sólo operaciones idempotentes soportadas |
| N21 | MUST P | Mutación verifica fence y dominio en misma frontera transaccional; predicado falso/zero-row aborta. Sin transacción distribuida IdP+D1. Callback remoto exitoso + fallo local deja acceso local denegado; no compensar creando permisos |
| N22 | MUST P | Lecturas sensibles comprueban fence antes de responder; store no disponible o réplica sin garantía necesaria ⇒ denegar. Writes ya committed antes de revoke no se deshacen. Restore no resucita sesión/epoch/tombstone; checkpoint confiable o reauth y bloqueo de activación |
| N23 | MUST P | SSO residual no reactiva una sesión local revocada. Nuevo intento tras revoke-all exige autenticación fresca verificable, no sólo prompt visual. Un refresh no renueva auth_time, prueba de credencial ni AdminAssurance |

La invalidación upstream de familia significa que sus refresh/descendientes ya no pueden emitir tokens; no se presume revocación instantánea de JWT offline. N20 hace inmediata la denegación en Frida tras el commit local. Reuse detectado sólo upstream requiere canal soportado de comprobación/evento y latencia documentada; hasta conocerlo, residual máximo de access300s más skew, salvo introspección/fence actualizado. No declarar latencia de eventos cero. Antes de activar debe fijarse y probarse esa composición, sin reemplazar N14 con un webhook tardío.

RFC 9700 permite alternativas de protección y no prescribe nuestra grace=0, TTL, número de dispositivos o taxonomía. RFC7009 tampoco garantiza por sí solo aislamiento por familia: esos MUST son Frida.

## Identidad, credenciales y recovery

| ID | Nivel / origen | Contrato |
|---|---|---|
| N24 | MUST P | AuthBinding(issuer,subject) único resuelve User opaco estable. Email, sub, credentialId y Provider no son User PK. Subject distinto no reconstruye historia |
| N25 | MUST P | Ningún auto-link/merge por email en database/social/passwordless/enterprise/import. Coincidencia o binding ocupado por otro User ⇒ conflicto fail-closed, no resolución heurística |
| N26 | MUST P | Linking existente: sesión legacy auténtica y reautenticada + prueba nueva dentro5min, mismo intento ≤10min, confirmación explícita; commit local único con ownership del binding y epochs. Legacy sin reauth acreditable ⇒ linking bloqueado |
| N27 | MUST P | Signup explícito crea User local sólo por contrato Frida atómico/versionado y sin conflicto. IdP no crea Pet ownership, Provider, admission/private_members ni grants. Cuenta del motor sola no admite cohorte |
| N28 | MUST P | Correo verificado mediante evidencia del motor/buzón confiable y versionada; no headers/contacto ni PATCH email_verified=true. Challenge ≤10min, one-use, OTP máximo5 intentos; anti-enumeración/rate limits. Prefetch de link no debe completar login sin interacción vinculada |
| N29 | MUST P | Journey viable sin contraseña obligatoria desde signup/enrolamiento hasta recuperación. Passkeys Consumer son método objetivo obligatorio a acreditar; email OTP/link puede servir bootstrap/fallback probado, no Admin UV |
| N30 | MUST P | Varias credenciales por misma identidad, listar/añadir/revocar mediante mecanismos soportados con reauth. Pérdida de dispositivo revoca familia; compromiso de passkey revoca todas copias de esa credencial, no sólo instalación. Passkey sincronizada no prueba hardware único |
| N31 | MUST P | Password fallback OFF en primera versión. Si proveedor conserva capacidad password interna, documentarla; no exigirla al usuario ni usar password fixture como PASS passwordless. Activarla requiere decisión futura, no concesión del adapter |
| N32 | MUST P | Recovery resuelve User preexistente por binding/caso auditado, no por email aislado. Email comprometido es riesgo Consumer explícito; prueba puede permitir recovery según política aprobada, nunca grants/assurance Admin. Ambigüedad bloquea y admite Support auditado |
| N33 | MUST P | Cambio email exige sesión reautenticada + prueba del nuevo buzón y control de colisión; User/binding estable, nuevo correo pendiente hasta prueba, aviso al anterior cuando posible. No trasladar historial por email. Compromiso/recovery incrementa epochs y revoca familias afectadas |
| N34 | SHOULD P | Segunda passkey independiente y avisos de seguridad; explicar sincronización/recovery. Falta de portabilidad automática exige alternativa probada de reenrollment |
| N35 | UX PREFERENCE | Login preferente con passkey, selección de cuenta clara, etiquetas de dispositivos útiles y mínimo copy/paste de OTP. Credential Manager nativo puede ser mejora posterior; no sustituye proof del browser flow |

Los endpoints de enrolamiento/recovery/email/credential deletion requieren pruebas de autorización, expiración, replay, concurrencia, notificación, anti-bruteforce y rate limits concretos del candidato. Ninguna credencial Consumer satisface Admin UV por inferencia.

## Plataformas

| ID | Nivel / origen | Contrato |
|---|---|---|
| N36 | MUST C S7/S8 | Android navegador externo/Custom Tab, no WebView; public client + S256. HTTPS App Link verificado por dominio, package y certificado de firma real; no callback con bearer/refresh ni clipboard ni secret APK |
| N37 | MUST P | Callback exacto scheme/host/path/port y query estática registrada; code/state dinámicos sólo parser permitido, sin parámetros duplicados/ambigüedad. state vincula intento/issuer/client/redirect; callback ajeno deniega antes de exchange |
| N38 | MUST P | Process death: persistir sólo intento mínimo cifrado/protegido por Keystore, TTL10min; sin verifier recuperable cancelar y relanzar login. One-use mediante transición atómica; duplicados/out-of-order no crean doble sesión. Code exchange con resultado ambiguo no se reintenta ciegamente |
| N39 | MUST P | Token storage privado cifrado; excluir backups/logs/analytics/URLs. Hijack de App Link, firma distinta, app ausente, reinstalación y sesión perdida son gates físicos; simulación browser no es PASS Android |
| N40 | MUST P | Web BFF Worker con tokens server-side cifrados, cookie opaca host-only __Host-, Path=/, HttpOnly, Secure, SameSite=Lax en callback top-level GET aprobado. No localStorage/JS bearer, no token en HTML/referrer |
| N41 | MUST P | CSRF token ligado a sesión + Origin exacto en mutaciones, Fetch Metadata complementario; SameSite no basta. No GET mutante; callback OIDC usa state y allowlist. form_post exigiría diseño de cookie específico, no desactivar protección |
| N42 | MUST P | Rotar SID al login/reauth, no adoptar SID del request. Raw Host/X-Forwarded-* no determina issuer/origin/redirect; proxies permitidos explícitos. Logout POST revoca y limpia cookie con mismos atributos; multi-tab sin refresh paralelo |
| N43 | MUST P | BFF sin cache de respuestas privadas, CSP y no terceros en callback. XSS puede actuar como User aun con HttpOnly: riesgo residual y revisión de front antes del rollout |
| N44 | MUST P | Admin client/audience/session separados; rechazar Consumer en Admin. AdminAssurance operación-específica del diseño Split Auth + RBAC, nunca emitida por IdP/refresh/email |

Ancla Android: package/certificado reales se mantienen en custodia privada; no son necesarios para K1 y no se publican en este paquete. El gate físico Android sigue separado.

## Exit y operación

| ID | Nivel | Gate |
|---|---|---|
| N45 | MUST | Export paginado verificable de cuentas/bindings/configuración/IDs y estado de revocación disponible; cifrado, conteos/checksums, minimización y restore ensayable. Frida conserva copia autoritativa de User y AuthBinding |
| N46 | MUST | Inventario de export de public keys, credentialId, userHandle, RP, algoritmos/counters/BE/BS si soportado. No declarar portabilidad sin import+autenticación probados. Jamás exportar claves privadas del autenticador |
| N47 | MUST | Si credenciales no transferibles: ruta soportada de reenrollment durante convivencia y recovery auditado tras salida, mismos User IDs sin email-merge. Sesiones/tokens no se migran; revocar y reautenticar, preservar tombstones. Sin ruta viable de salida ⇒ FAIL |
| N48 | SHOULD | RP/dominio bajo control Frida y continuidad contractual, export automatizable sin soporte manual. Cambio IdP conservando RP no garantiza por sí solo import. Admin RP/keys permanecen independientes |
| N49 | MUST | Plan post-trial identificado por feature/API; precio con moneda/fecha/unidad/MAU y extras verificable o cotización pendiente. UNKNOWN bloquea viabilidad comercial, no se fabrica precio |
| N50 | MUST | Cuotas/rate limits por endpoint, 429/retry-after, export/revoke recovery, SLA contractual o ausencia explícita, soporte/outage, región de datos/logs/backups/subprocesadores/DPA/retención/borrado. Aprobación de coste/privacidad antes de contratar |
| N51 | MUST | Inventario completo READ/WRITE por recurso, límites de tenant vs client/fixture, mínimo privilegio, cleanup/restore y readback. Scope extra/global/billing ⇒ autorización aparte, nunca autoelevar |
| N52 | MUST | API soportada para revocar familias/credenciales, recovery y export en plan sostenible. Trial PASS sólo acredita configuración temporal. Dependencias fijadas/auditadas y Worker compatible en proof separado; hold Sharp no se diluye |
| N53 | SHOULD | SLO de disponibilidad y latencias medibles de login/refresh/revoke/export; umbrales de negocio aprobados antes de rollout. Publicar UNKNOWN donde entorno no mida |
| N54 | UX PREFERENCE | Personalización visual, nombres de dispositivo y continuidad SSO cómoda sólo si no cambia fences ni freshness |

Lock-in aceptable propuesto: coste operativo de migración, fin de sesiones y reenrollment explícito viable. No aceptable: pérdida/reasignación de User/historia, salida sólo por merge de email, falta de revocación dirigida, ausencia de export esencial o dependencia permanente de entitlements no financiados.

## Fuentes primarias y precedencia

Consultadas 2026-10-10. Sin selección de proveedor ni nuevas consultas a tenant.
- S1 [RFC6749 §4.1.2–4.1.4/5.2](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.3).
- S2 [RFC7636 §4.3–4.6](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.6).
- S3 [OAuth2.1 draft16 §4.1.3/10.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-10.2); [estado IETF](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/). No RFC final al corte.
- S4 [RFC9700 §2.1/4.14](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2).
- S5 [OIDC Core errata set2 §3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).
- S6 [RFC8725 §3](https://www.rfc-editor.org/rfc/rfc8725.html).
- S7 [RFC8252 §4/7/8](https://www.rfc-editor.org/rfc/rfc8252.html).
- S8 [Android App Links verification](https://developer.android.com/training/app-links/verify-applinks).
- [RFC7009](https://www.rfc-editor.org/rfc/rfc7009.html) y [OIDC RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html): mecanismos, no garantía de todos los alcances Frida.
- Políticas propias: contrato aprobado CONSUMER-AUTH-INTEROP-01 y Split Auth. Referencias privadas omitidas de esta copia pública.

Cuando un RFC permite más opciones, la política Frida puede ser más estricta y se etiqueta P. Ningún adapter, harness o documentación comercial puede relajar estos requisitos durante el ensayo.

