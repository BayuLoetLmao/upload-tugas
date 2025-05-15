<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <title>RSA Enkripsi & Dekripsi</title>
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600&display=swap" rel="stylesheet">
  <style>
    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      font-family: 'Space Grotesk', sans-serif;
      background: linear-gradient(160deg, #0f2027, #203a43, #2c5364);
      color: #fff;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      padding: 20px;
    }

    .container {
      background: rgba(255, 255, 255, 0.06);
      backdrop-filter: blur(10px);
      padding: 30px 40px;
      border-radius: 20px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
      max-width: 500px;
      width: 100%;
    }

    h1 {
      text-align: center;
      margin-bottom: 25px;
      font-size: 1.8rem;
      color: #c0e8ff;
    }

    input[type="text"] {
      width: 100%;
      padding: 14px;
      font-size: 1rem;
      border-radius: 12px;
      border: none;
      margin-bottom: 20px;
      background-color: rgba(255, 255, 255, 0.15);
      color: #fff;
    }

    input::placeholder {
      color: #ccc;
    }

    .buttons {
      display: flex;
      gap: 10px;
      justify-content: space-between;
    }

    button {
      flex: 1;
      padding: 14px;
      font-size: 1rem;
      border: none;
      border-radius: 12px;
      background: linear-gradient(to right, #36d1dc, #5b86e5);
      color: #fff;
      font-weight: bold;
      cursor: pointer;
      transition: 0.3s ease;
    }

    button:hover {
      background: linear-gradient(to right, #5b86e5, #36d1dc);
    }

    .result {
      margin-top: 25px;
      background-color: rgba(0,0,0,0.3);
      padding: 15px;
      border-radius: 10px;
      color: #c8e0ff;
      word-wrap: break-word;
      font-size: 0.95rem;
    }
  </style>
</head>
<body>

  <div class="container">
    <h1>RSA Enkripsi & Dekripsi Nama</h1>
    <form method="POST">
      <input type="text" name="input_name" placeholder="Masukkan nama..." required />
      <div class="buttons">
        <button type="submit" name="encrypt">🔒 Enkripsi</button>
        <button type="submit" name="decrypt">🔓 Dekripsi</button>
      </div>
    </form>

    <?php
    function generateRSAKeys() {
        $p = 61;
        $q = 53;
        $n = $p * $q;
        $phi = ($p - 1) * ($q - 1);
        $e = 17;
        $d = modInverse($e, $phi);
        return [
            'public' => [$e, $n],
            'private' => [$d, $n]
        ];
    }

    function modInverse($a, $m) {
        $m0 = $m;
        $x0 = 0;
        $x1 = 1;
        while ($a > 1) {
            $q = intdiv($a, $m);
            $t = $m;
            $m = $a % $m;
            $a = $t;
            $t = $x0;
            $x0 = $x1 - $q * $x0;
            $x1 = $t;
        }
        return $x1 < 0 ? $x1 + $m0 : $x1;
    }

    function rsaEncrypt($text, $publicKey) {
        [$e, $n] = $publicKey;
        $result = [];
        for ($i = 0; $i < strlen($text); $i++) {
            $m = ord($text[$i]);
            $c = bcpowmod($m, $e, $n);
            $result[] = $c;
        }
        return base64_encode(implode(' ', $result));
    }

    function rsaDecrypt($encoded, $privateKey) {
        [$d, $n] = $privateKey;
        $decoded = base64_decode($encoded);
        $chunks = explode(' ', $decoded);
        $result = '';
        foreach ($chunks as $c) {
            $m = bcpowmod($c, $d, $n);
            $result .= chr($m);
        }
        return $result;
    }

    $keys = generateRSAKeys();
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        $name = $_POST["input_name"];
        $result = "";

        if (isset($_POST["encrypt"])) {
            $result = rsaEncrypt($name, $keys['public']);
        } elseif (isset($_POST["decrypt"])) {
            $result = rsaDecrypt($name, $keys['private']);
        }

        echo '<div class="result"><strong>Hasil:</strong><br>' . htmlspecialchars($result) . '</div>';
    }
    ?>
  </div>
</body>
</html>
