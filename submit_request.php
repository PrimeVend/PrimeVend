<?php
// ---------------------------
// PrimeVend: Secure Form Handler
// ---------------------------

// 1) Only allow POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  http_response_code(405);
  exit('Method Not Allowed');
}

// 2) Simple rate-limit by IP (one submit per 20 seconds)
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$store = sys_get_temp_dir() . '/pv_form_limiter_' . md5($ip);
$now = time();
if (file_exists($store)) {
  $last = (int)file_get_contents($store);
  if ($now - $last < 20) {
    http_response_code(429);
    exit('Please wait a moment before submitting again.');
  }
}
file_put_contents($store, (string)$now);

// 3) Honeypot (must exist in the form but be hidden from humans)
if (!empty($_POST['company_website'])) {
  // Silently succeed for bots
  header('Location: /thank-you.html');
  exit;
}

// 4) Helpers
function strip_injection($v) {
  // Remove line breaks & common header-injection tokens
  $v = str_replace(["\r", "\n", "%0a", "%0d"], '', (string)$v);
  return trim($v);
}
function required_text($key) {
  return strip_injection($_POST[$key] ?? '');
}

// 5) Gather & validate inputs
$name    = required_text('name');
$phone   = required_text('phone');
$email   = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL);
$biz     = required_text('business_name');
$addr    = required_text('business_address');
$daily   = (int)($_POST['daily_people'] ?? 0);
$message = trim((string)($_POST['message'] ?? ''));

$errors = [];
if ($name === '')   $errors[] = 'Full Name is required.';
if ($phone === '')  $errors[] = 'Phone Number is required.';
if (!$email)        $errors[] = 'Valid Email Address is required.';
if ($biz === '')    $errors[] = 'Business Name is required.';
if ($addr === '')   $errors[] = 'Business Address is required.';
if ($daily < 1)     $errors[] = 'Daily people must be at least 1.';

if ($errors) {
  http_response_code(400);
  // Show a basic error page; you can style this later.
  echo "Please fix the following:<br>" . implode('<br>', array_map('htmlspecialchars', $errors));
  exit;
}

// 6) Compose email
$to       = 'info@primevend.com'; // TODO: change to your destination email
$subject  = 'New Vending Machine Request';
$body = "A new vending request was submitted:\n\n"
      . "Name:           {$name}\n"
      . "Phone:          {$phone}\n"
      . "Email:          {$email}\n"
      . "Business:       {$biz}\n"
      . "Address:        {$addr}\n"
      . "Daily People:   {$daily}\n"
      . "Message:\n{$message}\n"
      . "\n---\nIP: {$ip}\nTime: " . date('c') . "\n";

// Use a domain you control for From (prevents SPF/DMARC issues)
$headers  = "From: PrimeVend Website <no-reply@primevend.com>\r\n";
$headers .= "Reply-To: {$email}\r\n";
$headers .= "X-Mailer: PHP/" . phpversion();

// 7) Send mail (native). For higher reliability, set up SMTP later.
$sent = @mail($to, $subject, $body, $headers);

if ($sent) {
  header('Location: /thank-you.html');
  exit;
}

http_response_code(500);
echo 'There was an issue sending your request. Please try again later.';
