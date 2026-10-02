<?php
/**
 * Contacto - Root Heim Company
 * Recibe el POST del formulario de contact.html (enviado por AJAX vía
 * js/contact.js), valida los datos y el captcha, envía el mensaje vía SMTP
 * (Gmail) con un correo HTML que incluye el logo de la empresa y responde
 * en JSON para que el resultado se muestre en el propio formulario.
 *
 * El "From" del correo se toma directamente del correo que escribió la
 * persona en el formulario. Gmail exige que el From coincida con la cuenta
 * autenticada, así que si lo rechaza se reintenta automáticamente usando
 * la cuenta configurada (RH_MAIL_FROM) y se deja el correo del remitente
 * en Reply-To para que la respuesta le llegue a él.
 */

require_once __DIR__ . '/form-helpers.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

function respondJson($ok, $message)
{
    header('Content-Type: application/json');
    echo json_encode(['ok' => $ok, 'message' => $message]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: contact.html');
    exit;
}

if (!isset($_POST['name'], $_POST['email'], $_POST['message'])) {
    respondJson(false, 'No se recibieron los datos del formulario. Vuelve a intentarlo.');
}

// Honeypot anti-spam (campo oculto que los humanos no llenan)
if (rh_is_honeypot_triggered()) {
    respondJson(false, 'Tu envío no pudo procesarse.');
}

// Límite de envíos por sesión, además del captcha (defensa adicional)
if (rh_rate_limited('contact', 15)) {
    respondJson(false, 'Ya recibimos tu mensaje. Espera unos segundos antes de enviar otro.');
}

// Google reCAPTCHA v2 (claves en mail-config.php)
function verifyCaptcha($response)
{
    $secret = RH_RECAPTCHA_SECRET;
    $url    = 'https://www.google.com/recaptcha/api/siteverify';
    $data   = http_build_query([
        'secret'   => $secret,
        'response' => $response,
        'remoteip' => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '',
    ]);

    // Preferimos cURL (más fiable que file_get_contents con SSL en XAMPP).
    if (function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        $result = curl_exec($ch);
        curl_close($ch);
        if ($result === false) {
            return false;
        }
        $json = json_decode($result, true);
        return !empty($json['success']);
    }

    // Fallback: file_get_contents CON verificación SSL activa. Si el
    // servidor no tiene un cacert.pem configurado, se debe corregir eso
    // (no desactivar la verificación, ya que permitiría a un atacante en
    // medio de la red falsificar la respuesta de reCAPTCHA y saltarse el
    // captcha por completo).
    $ctx = stream_context_create([
        'http' => [
            'method'  => 'POST',
            'header'  => 'Content-Type: application/x-www-form-urlencoded',
            'content' => $data,
            'timeout' => 10,
        ],
        'ssl' => [
            'verify_peer'       => true,
            'verify_peer_name'  => true,
        ],
    ]);
    $result = @file_get_contents($url, false, $ctx);
    if ($result === false) {
        return false;
    }
    $json = json_decode($result, true);
    return !empty($json['success']);
}

if (!isset($_POST['g-recaptcha-response']) || !verifyCaptcha($_POST['g-recaptcha-response'])) {
    respondJson(false, 'Por favor completa el captcha para continuar.');
}

$name    = trim($_POST['name']);
$email   = trim($_POST['email']);
$message = trim($_POST['message']);

$errors = [];

if ($name === '' || !preg_match('/^[A-Za-zÁÉÍÓÚÑáéíóúñ .\'-]+$/u', $name)) {
    $errors[] = 'El nombre no es válido.';
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = 'El correo electrónico no es válido.';
}
if (strlen($message) < 2) {
    $errors[] = 'El mensaje debe tener al menos 2 caracteres.';
}
if (RH_SMTP_PASS === '' || RH_SMTP_PASS === 'TU_APP_PASSWORD_AQUI') {
    $errors[] = 'Falta configurar el envío de correo (RH_SMTP_PASS en mail-config.php).';
}
if (!empty($errors)) {
    respondJson(false, 'Lo sentimos: ' . implode(' ', $errors));
}

$logoPath = __DIR__ . '/images/logo-light.png';
$nameHtml    = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
$emailHtml   = htmlspecialchars($email, ENT_QUOTES, 'UTF-8');
$messageHtml = nl2br(htmlspecialchars($message, ENT_QUOTES, 'UTF-8'));

// --- Cuerpo HTML del correo -----------------------------------------------
$bodyHtml = <<<HTML
<div style="background:#f3f6fa;padding:40px 16px;font-family:Arial,Helvetica,sans-serif;">
  <table role="presentation" cellpadding="0" cellspacing="0"
    style="width:100%;max-width:620px;margin:0 auto;background:#ffffff;border-radius:14px;border:1px solid #e2e8f0;overflow:hidden;">

    <!-- Header -->
    <tr>
      <td style="background:#0b1526;padding:28px 32px;text-align:center;">
        <img src="cid:rh_logo"
          alt="Root Heim Company"
          style="height:52px;max-width:220px;width:auto;display:block;margin:0 auto;">
      </td>
    </tr>

    <!-- Content -->
    <tr>
      <td style="padding:36px 38px 30px;">

        <p style="margin:0 0 8px;color:#1f4fd8;font-size:12px;font-weight:bold;letter-spacing:1px;text-transform:uppercase;">
          Formulario de contacto
        </p>

        <h2 style="margin:0 0 10px;color:#14202e;font-size:24px;line-height:1.3;">
          Nuevo mensaje recibido
        </h2>

        <p style="margin:0 0 30px;color:#687386;font-size:14px;line-height:1.6;">
          Has recibido un nuevo mensaje desde el sitio web de
          <strong style="color:#3b4555;">Root Heim Company</strong>.
        </p>

        <!-- Información del remitente -->
        <table role="presentation" cellpadding="0" cellspacing="0"
          style="width:100%;background:#f7f9fc;border:1px solid #edf1f6;border-radius:10px;">

          <tr>
            <td style="padding:18px 20px 8px;color:#8993a5;font-size:12px;">
              REMITENTE
            </td>
          </tr>

          <tr>
            <td style="padding:0 20px 18px;color:#172235;font-size:15px;font-weight:bold;">
              {$nameHtml}
            </td>
          </tr>

          <tr>
            <td style="padding:0 20px 8px;color:#8993a5;font-size:12px;">
              CORREO ELECTRÓNICO
            </td>
          </tr>

          <tr>
            <td style="padding:0 20px 20px;font-size:14px;">
              <a href="mailto:{$emailHtml}"
                style="color:#1f4fd8;text-decoration:none;font-weight:bold;">
                {$emailHtml}
              </a>
            </td>
          </tr>

        </table>

        <!-- Mensaje -->
        <p style="margin:30px 0 10px;color:#8993a5;font-size:12px;font-weight:bold;letter-spacing:.5px;text-transform:uppercase;">
          MENSAJE
        </p>

        <table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;">
          <tr>
            <td style="
              padding:20px 22px;
              background:#ffffff;
              border:1px solid #e4e9f1;
              border-left:4px solid #1f4fd8;
              border-radius:8px;
              color:#30394a;
              font-size:14px;
              line-height:1.8;
            ">
              {$messageHtml}
            </td>
          </tr>
        </table>

        <!-- Botón -->
        <table role="presentation" cellpadding="0" cellspacing="0"
          style="width:100%;margin-top:30px;">
          <tr>
            <td style="text-align:center;">
              <a href="mailto:{$emailHtml}"
                style="
                  display:inline-block;
                  background:#1f4fd8;
                  color:#ffffff;
                  text-decoration:none;
                  font-size:14px;
                  font-weight:bold;
                  padding:13px 24px;
                  border-radius:7px;
                ">
                Responder al remitente
              </a>
            </td>
          </tr>
        </table>

      </td>
    </tr>

    <!-- Footer -->
    <tr>
      <td style="padding:20px 32px;background:#f8fafc;border-top:1px solid #edf1f6;text-align:center;">
        <p style="margin:0;color:#9aa4b5;font-size:11px;line-height:1.6;">
          Este mensaje fue enviado automáticamente desde el sitio web
          <strong style="color:#687386;">Root Heim Company</strong>.
        </p>
      </td>
    </tr>

  </table>
</div>
HTML;

function buildMail($fromEmail, $fromName, $name, $email, $message, $bodyHtml, $logoPath)
{
    $mail = new PHPMailer(true);
    $mail->isSMTP();
    $mail->Host       = RH_SMTP_HOST;
    $mail->SMTPAuth   = true;
    $mail->Username   = RH_SMTP_USER;
    $mail->Password   = RH_SMTP_PASS;
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
    $mail->Port       = RH_SMTP_PORT;

    $mail->CharSet = 'UTF-8';
    $mail->setFrom($fromEmail, $fromName);
    $mail->addAddress(RH_MAIL_TO, RH_MAIL_TO_NAME);
    $mail->addReplyTo($email, $name);

    if (is_file($logoPath)) {
        $mail->addEmbeddedImage($logoPath, 'rh_logo', 'logo.png');
    }

    $mail->isHTML(true);
    $mail->Subject = RH_MAIL_SUBJECT;
    $mail->Body    = $bodyHtml;
    $mail->AltBody = "Nuevo mensaje desde el formulario de contacto\n\n"
                   . "Nombre:    " . $name . "\n"
                   . "Correo:    " . $email . "\n"
                   . "Mensaje:\n" . $message . "\n";

    return $mail;
}

try {
    // Primer intento: From = el correo que escribió la persona
    buildMail($email, $name, $name, $email, $message, $bodyHtml, $logoPath)->send();
} catch (Exception $e) {
    try {
        // Gmail exige From = cuenta autenticada: reintenta con la cuenta y Reply-To al remitente
        error_log('RH contact: From del formulario rechazado, reintentando con cuenta (' . $e->getMessage() . ')');
        buildMail(RH_MAIL_FROM, RH_MAIL_TO_NAME, $name, $email, $message, $bodyHtml, $logoPath)->send();
    } catch (Exception $e2) {
        error_log('RH contact mail error: ' . $e->getMessage() . ' | ' . $e2->getMessage());
        respondJson(false, 'Hubo un problema al enviar el correo. Inténtalo de nuevo más tarde.');
    }
}

respondJson(true, 'Pronto nos comunicaremos con usted.');