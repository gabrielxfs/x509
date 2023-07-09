import * as x509 from "@peculiar/x509";
import { Crypto } from "@peculiar/webcrypto";

const crypto = new Crypto();
x509.cryptoProvider.set(crypto);

const alg = {
  name: "RSASSA-PKCS1-v1_5",
  hash: "SHA-256",
  publicExponent: new Uint8Array([1, 0, 1]),
  modulusLength: 2048,
};
const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);
const cert = await x509.X509CertificateGenerator.createSelfSigned({
  serialNumber: "01",
  name: "CN=Test",
  notBefore: new Date("2023/05/22"),
  notAfter: new Date("2024/11/22"),
  signingAlgorithm: alg,
  keys,
  extensions: [
    new x509.BasicConstraintsExtension(true, 2, true),
    new x509.ExtendedKeyUsageExtension(["1.2.3.4.5.6.7", "2.3.4.5.6.7.8"], true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
  ]
});

console.log(cert.toString("pem")); // Certificate in PEM format
