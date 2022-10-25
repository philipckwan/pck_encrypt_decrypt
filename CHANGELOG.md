For pck_encrypt_decrypt.sh (Linux bash script):

-v1.5 (20220419)
1) tag keys support
2) add salts for encryption in tag mode

-v1.6 (20220428)
fix an issue with handling windows/dos type of text file, tag key matching does not work because of the
 newline/linefeed difference between dos and unix

-v1.7 (20220915)
use something like line.substring() to search for tag_key_head and tag_key_tail, so that the encrypted tag can be inside the line, any drawback?

-v1.8  (20221015)
add options to encrypt and decrypt from reading stdin
also for the stdin option, enhance it to use pbcopy (copy to clipboard)

-v1.9, v1.10
1) password length and character limit check
2) further deviate the encryption by adding multiple encryption rounds, prevent close enough password to be able to decrypt the encrypted text
3) the salt and multiple encryption rounds will support all 3 modes: stdin, whole file, tag keys


---------------------------------------
For win_pck_encrypt_decrypt.ps1 (Windows powershell script):

-v0.3
Initial version