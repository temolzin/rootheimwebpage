<?php
/**
 * Configuración de correo (Root Heim Company)
 * =============================================
 * Para que los correos lleguen de verdad se usa Gmail SMTP con una
 * "contraseña de aplicación" (App Password). Genera una en:
 *   https://myaccount.google.com/apppasswords
 * (Activa primero la verificación en 2 pasos de tu cuenta).
 */

define('RH_SMTP_HOST', 'mail.rootheim.com');
define('RH_SMTP_PORT', 465);
define('RH_SMTP_USER', 'info@rootheim.com');
define('RH_SMTP_PASS', 'U<vrV0B&mn4k1:rNGa>^QB8s');

define('RH_MAIL_TO',      'info@rootheim.com');
define('RH_MAIL_FROM',    'info@rootheim.com');
define('RH_MAIL_TO_NAME', 'Root Heim Company');
define('RH_MAIL_SUBJECT', 'Contacto desde la web - Root Heim Company');

/**
 * Google reCAPTCHA v2 (casilla)
 * Genera tus claves en: https://www.google.com/recaptcha/admin
 * RH_RECAPTCHA_SITE  -> va en el frontend en contact.html (es pública).
 * RH_RECAPTCHA_SECRET-> SOLO backend, nunca debe ir en el HTML.
 * IMPORTANTE: el dominio usado para probar el sitio debe estar registrado
 * en las claves (add localhost / IP en el admin de reCAPTCHA).
 */

define('RH_RECAPTCHA_SITE',   '6LfR0sctAAAAAJ9YZAqrZ3QehBAIAP_2y9fq_EdJ');
define('RH_RECAPTCHA_SECRET', '6LfR0sctAAAAAPnRWFUtpWYgrpPWh2vJCSNaA8jn');