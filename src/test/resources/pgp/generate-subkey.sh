export GNUPGHOME="$(mktemp -d)"

gpg --batch --gen-key <<EOF
Key-Type: EDDSA
Key-Curve: ed25519
Key-Usage: sign
Subkey-Type: ECDH
Subkey-Curve: cv25519
Subkey-Usage: encrypt
Name-Real: Kestra
Name-Comment: for unit test
Name-Email: ed25519@kestra.io
Expire-Date: 0
Passphrase: abc456
%commit
EOF

gpg --batch --gen-key <<EOF
Key-Type: RSA
Key-Length: 3072
Key-Usage: sign
Subkey-Type: RSA
Subkey-Length: 3072
Subkey-Usage: encrypt
Name-Real: Kestra
Name-Comment: for unit test
Name-Email: rsa-subkey@kestra.io
Expire-Date: 0
Passphrase: abc456
%commit
EOF

gpg --batch --gen-key <<EOF
Key-Type: DSA
Key-Length: 2048
Key-Usage: sign
Subkey-Type: ELG-E
Subkey-Length: 2048
Subkey-Usage: encrypt
Name-Real: Kestra
Name-Comment: for unit test
Name-Email: dsa-elgamal@kestra.io
Expire-Date: 0
Passphrase: abc456
%commit
EOF

for VALUE in ed25519 rsa-subkey dsa-elgamal
do
  gpg --armor --export "$VALUE@kestra.io" > $VALUE-key.pub
  gpg --batch --pinentry-mode loopback --passphrase abc456 --armor --export-secret-key "$VALUE@kestra.io" > $VALUE-key.sec
done

rm -rf "$GNUPGHOME"
