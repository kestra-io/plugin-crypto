# How to use the Crypto plugin

Encrypt and decrypt files using OpenPGP from Kestra flows.

## Tasks

`openpgp.Encrypt` encrypts a file with one or more recipients' public keys — set `recipients` (required, list of recipient email addresses) and `key` (the ASCII-exported public key). To also sign the output, set `signPublicKey`, `signPrivateKey`, `signPassphrase`, and `signUser`. Set `from` to the `kestra://` URI of the file to encrypt. The output includes `uri` (the encrypted file).

`openpgp.Decrypt` decrypts a PGP-encrypted file — set `from` (the `kestra://` URI of the encrypted file), `privateKey` (ASCII-exported private key), and `privateKeyPassphrase` (if the key is passphrase-protected). To verify the signature, set `signUsersKey` (list of public keys) and optionally `requiredSignerUsers` (list of email addresses that must have signed). The output includes `uri` (the decrypted file).

Store keys and passphrases in [secrets](https://kestra.io/docs/concepts/secret) and apply them globally with [plugin defaults](https://kestra.io/docs/workflow-components/plugin-defaults).
