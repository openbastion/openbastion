import { Account } from "../../shared/api";

// Whoever changes a pin decides which server receives the secret: the Vault audits it. Both
// questions cancel the whole gesture (null), and nothing is sent.

export function askHostKey(a: Account): string | null {
  return window.prompt(
    `Clé d'hôte publique de ${a.targetHost} (une ligne « ssh-ed25519 AAAA… », relevée sur la cible : /etc/ssh/ssh_host_*_key.pub).` +
      (a.hostKeyFingerprint ? ` Elle remplace ${a.hostKeyFingerprint} : ne le faites que si la cible a réellement changé de clé.` : ""),
  );
}

// The same decision for a graphical target: this certificate, for this name, gets the secret.
export function askTlsPin(a: Account): { fingerprint: string; domain: string } | null {
  const fingerprint = window.prompt(
    `Empreinte SHA-256 du certificat TLS de ${a.targetHost}, relevée sur la cible (openssl x509 -in cert.pem -outform der | sha256sum).` +
      (a.tlsCertificateSha256 ? ` Elle remplace ${a.tlsCertificateSha256} : ne le faites que si la cible a réellement changé de certificat.` : ""),
  );
  if (!fingerprint) return null;
  const domain = window.prompt(`Nom pour lequel ce certificat est valide (DNS ou IP).`, a.targetDomain ?? "");
  if (!domain) return null;
  return { fingerprint: fingerprint.trim(), domain: domain.trim() };
}
