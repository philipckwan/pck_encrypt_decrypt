For pck_encrypt_decrypt.sh (Linux bash script):

-v1.14 (20240403)
1) Add mode "encic" to encrypt text from interactive mode, and copy to clipboard

-v1.13 (20240303)
1) Enhanced the output display when decrypting, especially displaying more information with multiple matched lines when decrypting
2) Change the checking of the command "pbcopy", which is only a mac supported command. In other Linux if this command is not available, it will give a more appropiate error message only if the selected mode requires copying to clipboard.

-v1.12 (20240219)
1) Added mode "decc" to decrypt from file with a tag, and only decrypt and copy the first matched tag to clipboard.
 This is a feature that helps people to directly decrypt a password and use it by pasting it right away.
 
-v1.11 (20230302)
1) for inteactive mode and file tag mode, add more security by allowing password with duplicate characters to further shuffle the text
2) fix issue in interactive mode where the special character '\' is not supported previously
3) Please note that there is a maximum character limit in using the interactive mode.
 For example, using a Mac terminal, running the linux version, the interactive mode only supports to input or paste up to 1024 characters. Currently, this issue is beyond the scope of this tool.
 The workaround is to use file based and tag mode to encrypt/decrypt such a long line

-v1.9, v1.10
1) password length and character limit check
2) further deviate the encryption by adding multiple encryption rounds, prevent close enough password to be able to decrypt the encrypted text
3) the salt and multiple encryption rounds will support all 3 modes: stdin, whole file, tag keys

-v1.8  (20221015)
add options to encrypt and decrypt from reading stdin
also for the stdin option, enhance it to use pbcopy (copy to clipboard)

-v1.7 (20220915)
use something like line.substring() to search for tag_key_head and tag_key_tail, so that the encrypted tag can be inside the line, any drawback?

-v1.6 (20220428)
fix an issue with handling windows/dos type of text file, tag key matching does not work because of the
 newline/linefeed difference between dos and unix

-v1.5 (20220419)
1) tag keys support
2) add salts for encryption in tag mode


---------------------------------------
For win_pck_encrypt_decrypt.ps1 (Windows powershell script):

-v1.0
pdate the version to v1.0, plus minor fix

-v0.4
port enhancements from linux script v1.10

-v0.3
Initial version