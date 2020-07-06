for VALUE in hello contact
do
  gpg --batch --gen-key <<EOF
  %echo Generating a basic $VALUE OpenPGP key
  Key-Type: RSA
  Key-Length: 1024
  Subkey-Type: ELG-E
  Subkey-Length: 1024
  Name-Real: Kestra
  Name-Comment: for unit test
  Name-Email: ${VALUE}@kestra.io
  Expire-Date: 0
  Passphrase: abc456
  %pubring ./${VALUE}.pub
  %secring ./${VALUE}.sec
  # Do a commit here, so that we can later print "done" :-)
  %commit
  %echo $VALUE done
EOF
  gpg --no-default-keyring --secret-keyring ./$VALUE.sec --keyring ./$VALUE.pub --list-secret-keys
  gpg --no-default-keyring --secret-keyring ./$VALUE.sec --keyring ./$VALUE.pub --edit-key "$VALUE@kestra.io"
  gpg --no-default-keyring --secret-keyring ./$VALUE.sec --keyring ./$VALUE.pub --armor --export -a "$VALUE@kestra.io" > $VALUE-key.pub
  gpg --no-default-keyring --secret-keyring ./$VALUE.sec --keyring ./$VALUE.pub --armor --export-secret-key -a "$VALUE@kestra.io" > $VALUE-key.sec
done
