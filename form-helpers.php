<?php
/**
 * form-helpers.php - Root Heim Company
 * =====================================
 * Funciones comunes de validación y envío de correo para TODOS los
 * formularios del sitio (contact.php, workform.php, teamcontact.php,
 * sub12.php, newsletter.php).
 *
 * Objetivo: que ningún dato de $_POST llegue nunca crudo a una cabecera
 * de correo (From/Reply-To/Bcc/Cc), que es la causa de la inyección de
 * cabeceras (header injection) que hacía vulnerable a sub12.php.
 *
 * TODO el correo se envía siempre a RH_MAIL_TO (info@rootheim.com,
 * definido en mail-config.php). Nunca se usa el correo del visitante
 * como "From" real: solo se usa, ya validado, como "Reply-To".
 */

require_once __DIR__ . '/mail-config.php';
require_once __DIR__ . '/mailer/Exception.php';
require_once __DIR__ . '/mailer/PHPMailer.php';
require_once __DIR__ . '/mailer/SMTP.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/** Corta cualquier intento de inyección de cabeceras (CRLF) y recorta longitud. */
function rh_clean_text($value, $maxLength = 1000)
{
    $value = (string) $value;
    $value = str_replace(["\r", "\n", "\0"], '', $value);
    $value = trim($value);
    if (function_exists('mb_substr')) {
        $value = mb_substr($value, 0, $maxLength);
    } else {
        $value = substr($value, 0, $maxLength);
    }
    return $value;
}

/** Nombre: solo letras (con acentos), espacios, apóstrofo y guion. */
function rh_validate_name($value)
{
    $value = rh_clean_text($value, 120);
    if ($value === '' || !preg_match('/^[A-Za-zÁÉÍÓÚÑÜáéíóúñü .\'-]+$/u', $value)) {
        return false;
    }
    return $value;
}

/** Correo: validación estándar de PHP; además se descarta cualquier CRLF. */
function rh_validate_email($value)
{
    $value = rh_clean_text($value, 190);
    $value = filter_var($value, FILTER_VALIDATE_EMAIL);
    return $value !== false ? $value : false;
}

/** Teléfono: solo dígitos, espacios, +, -, paréntesis. Nada de letras ni símbolos de cabecera. */
function rh_validate_phone($value)
{
    $value = rh_clean_text($value, 30);
    if ($value === '' || !preg_match('/^[0-9+()\s-]{6,30}$/', $value)) {
        return false;
    }
    return $value;
}

/** Sitio web: solo lo necesario para un dominio/URL simple. */
function rh_validate_site($value)
{
    $value = rh_clean_text($value, 190);
    if ($value === '' || !preg_match('/^[A-Za-z0-9.:\/_-]+$/', $value)) {
        return false;
    }
    return $value;
}

/** Mensaje libre: se limpia de CRLF/nulos, se limita longitud y se escapa al mostrarlo. */
function rh_validate_message($value, $minLength = 2, $maxLength = 5000)
{
    $value = rh_clean_text($value, $maxLength);
    if (mb_strlen($value) < $minLength) {
        return false;
    }
    return $value;
}

/**
 * Honeypot anti-bot: un campo oculto (ej. "rh_website") que un humano
 * nunca llena porque no lo ve, pero los bots sí. Si viene lleno, se
 * trata como spam sin decírselo al bot (para no darle pistas).
 */
function rh_is_honeypot_triggered($fieldName = 'rh_website')
{
    return !empty($_POST[$fieldName]);
}

/**
 * Limita envíos por sesión: evita que un mismo visitante (o script)
 * spamee el formulario a repetición. No sustituye un CAPTCHA, pero
 * detiene el abuso más simple sin pedirle nada extra al usuario.
 */
function rh_rate_limited($formKey, $seconds = 20)
{
    $now     = time();
    $lastKey = 'rh_last_submit_' . $formKey;
    if (isset($_SESSION[$lastKey]) && ($now - $_SESSION[$lastKey]) < $seconds) {
        return true;
    }
    $_SESSION[$lastKey] = $now;
    return false;
}

/**
 * Envía el correo SIEMPRE a RH_MAIL_TO, con From = cuenta propia
 * (Gmail exige que From coincida con la cuenta autenticada). El correo
 * del visitante, ya validado, se usa como Reply-To para poder
 * contestarle directo. Si no hay correo válido del visitante, no se
 * agrega Reply-To.
 *
 * Devuelve true/false; nunca imprime detalles del error al visitante.
 */
function rh_send_mail($subject, $bodyHtml, $bodyText, $replyToEmail = null, $replyToName = '')
{
    try {
        $mail = new PHPMailer(true);
        $mail->isSMTP();
        $mail->Host       = RH_SMTP_HOST;
        $mail->SMTPAuth   = true;
        $mail->Username   = RH_SMTP_USER;
        $mail->Password   = RH_SMTP_PASS;
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
        $mail->Port       = RH_SMTP_PORT;
        $mail->CharSet    = 'UTF-8';

        $mail->setFrom(RH_MAIL_FROM, RH_MAIL_TO_NAME);
        $mail->addAddress(RH_MAIL_TO, RH_MAIL_TO_NAME);

        if ($replyToEmail) {
            // PHPMailer valida internamente el formato antes de usarlo.
            $mail->addReplyTo($replyToEmail, $replyToName ?: $replyToEmail);
        }

        $mail->isHTML(true);
        $mail->Subject = $subject;
        $mail->Body    = $bodyHtml;
        $mail->AltBody = $bodyText;

        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log('RH mail error: ' . $e->getMessage());
        return false;
    }
}

/** Envuelve el contenido en la misma plantilla visual que usa contact.php. */
function rh_mail_template($title, $rowsHtml)
{
    return <<<HTML
<div style="background:#f3f6fa;padding:40px 16px;font-family:Arial,Helvetica,sans-serif;">
  <table role="presentation" cellpadding="0" cellspacing="0"
    style="width:100%;max-width:620px;margin:0 auto;background:#ffffff;border-radius:14px;border:1px solid #e2e8f0;overflow:hidden;">
    <tr>
      <td style="background:#0b1526;padding:28px 32px;text-align:center;">
        <span style="color:#ffffff;font-size:18px;font-weight:bold;">Root Heim Company</span>
      </td>
    </tr>
    <tr>
      <td style="padding:36px 38px 30px;">
        <h2 style="margin:0 0 20px;color:#14202e;font-size:22px;">{$title}</h2>
        <table role="presentation" cellpadding="0" cellspacing="0"
          style="width:100%;background:#f7f9fc;border:1px solid #edf1f6;border-radius:10px;">
          {$rowsHtml}
        </table>
      </td>
    </tr>
    <tr>
      <td style="padding:20px 32px;background:#f8fafc;border-top:1px solid #edf1f6;text-align:center;">
        <p style="margin:0;color:#9aa4b5;font-size:11px;">Enviado automáticamente desde rootheim.com</p>
      </td>
    </tr>
  </table>
</div>
HTML;
}

function rh_mail_row($label, $valueHtml)
{
    $labelHtml = htmlspecialchars($label, ENT_QUOTES, 'UTF-8');
    return <<<HTML
    <tr>
      <td style="padding:14px 20px 4px;color:#8993a5;font-size:12px;text-transform:uppercase;">{$labelHtml}</td>
    </tr>
    <tr>
      <td style="padding:0 20px 10px;color:#172235;font-size:14px;">{$valueHtml}</td>
    </tr>
HTML;
}
