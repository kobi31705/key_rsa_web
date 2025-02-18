const { bigInt } = window;

let publicKey = '';
let privateKey = '';

// 키 생성
document.getElementById('generate-keys').addEventListener('click', () => {
  function isPrime(num) {
    return bigInt(num).isProbablePrime(10);
  }

  function generatePrime(bits) {
    let prime;
    do {
      prime = bigInt.randBetween(bigInt(2).pow(bits - 1), bigInt(2).pow(bits).minus(1));
    } while (!isPrime(prime));
    return prime;
  }

  function generateRSAKeys() {
    const bitLength = 256; // 128비트로 설정
    const e = bigInt(65537);

    const p = generatePrime(bitLength / 2);
    const q = generatePrime(bitLength / 2);

    const n = p.multiply(q);
    const phi = p.minus(1).multiply(q.minus(1));

    const d = e.modInv(phi);

    return { publicKey: { n, e }, privateKey: { n, d } };
  }

  const keys = generateRSAKeys();
  publicKey = keys.publicKey;
  privateKey = keys.privateKey;

  document.getElementById("keys").innerText = `Public Key (n, e):\n${keys.publicKey.n.toString()}, ${keys.publicKey.e.toString()}\n\nPrivate Key (n, d):\n${keys.privateKey.n.toString()}, ${keys.privateKey.d.toString()}`;
});

// 암호화
document.getElementById('encrypt').addEventListener('click', () => {
  const plainText = document.getElementById('message').value;

  if (plainText && publicKey) {
    const encoder = new TextEncoder();
    const encodedText = encoder.encode(plainText);

    // 큰 숫자로 변환
    let bigIntArray = bigInt(0);
    for (let i = 0; i < encodedText.length; i++) {
      bigIntArray = bigIntArray.shiftLeft(8).add(bigInt(encodedText[i]));
    }

    // 공개키로 암호화: M^e % n
    const encrypted = bigIntArray.modPow(publicKey.e, publicKey.n);

    // 암호문이 n보다 클 경우 처리할 수 없으므로 알림
    if (encrypted.greater(publicKey.n)) {
      alert('Encrypted message is too large for the key size.');
    } else {
      document.getElementById('encrypted').textContent = `Encrypted Message: ${encrypted.toString()}`;
    }
  } else {
    alert('Please generate keys and enter a message to encrypt.');
  }
});

// 복호화
document.getElementById('decrypt').addEventListener('click', () => {
  const cipherText = document.getElementById('cipher').value;

  if (cipherText && privateKey) {
    try {
      // 암호문을 bigInt로 변환
      const encryptedBigInt = bigInt(cipherText);

      // 복호화: C^d % n
      const decryptedBigInt = encryptedBigInt.modPow(privateKey.d, privateKey.n);

      // 복호화된 메시지를 Uint8Array로 변환
      const decryptedStr = decryptedBigInt.toString(16); // 16진수로 변환

      // 16진수로 변환된 값을 다시 바이트 배열로 변환
      let byteArray = [];
      for (let i = 0; i < decryptedStr.length; i += 2) {
        byteArray.push(parseInt(decryptedStr.substr(i, 2), 16));
      }

      // Uint8Array로 변환 후, 텍스트로 복원
      const uint8Array = new Uint8Array(byteArray);
      const decoder = new TextDecoder();
      const decryptedText = decoder.decode(uint8Array);

      document.getElementById('decrypted').textContent = `Decrypted Message: ${decryptedText}`;
    } catch (err) {
      alert('Decryption failed. Ensure you used the correct key and message.');
    }
  } else {
    alert('Please generate keys and enter a message to decrypt.');
  }
});
