PCK Encrypt Decrypt
=

PCK Encrypt Decrypt is a shell script, Linux commands based tool that can encrypt and decrypt data files.
It also has the capability to partially encrypt/decrypt text files.

Features
-

This tool:
* can encrypt and decrypt a whole binary file, in any format. The results is Base64 text, in other words, the character sets of Base64
* can encrypt and decrypt a segment of a plaintext file. The key is to enclose such text in xml like element as an identifier
* the results of the encryption and decryption can be outputted in the terminal, thus only in memory. Or it can be outputted into a file, which means it will be persisted into the filesystem.
* The encryption and decryption technology is based on base64 encoding and followed by a text shuffling, based on a passphrase setup by the user upon encryption

Command Arguments
-

pck_encrypt_decrypt.sh <filepath> <encrypt option> [<tag key>]"
* filepath: relative path and filename, pointing to the file
* encrypt option: enc | dec | encf | decf
 enc - encrypt in memory, showing the results in console
 dec - decrypt in memory, showing the results in console
 encf - encrypt and output to file
 decf - decrypt and output to file
* tag key: < and > will be added to enclose tag key; i.e. pck-01 becomes <pck-01> and </pck-01>"
 it is expected the tag is enlosed like xml tags, i.e. <pck-01> and </pck-01> enclosed the inline text to be encrypted"
 if <tag key> is not provided, it will assume the whole file needs to be encrypted/decrypted"

Examples
-

Example 1 - encrypt a whole binary file

This command encrypts the whole pdf file in the test directory:
$ ./pck_encrypt_decrypt.sh test/Philip_substack_cryptography.pdf encf 

The output is saved as a new file Philip_substack_cryptography.pdf.encf in the same folder.
I entered "ironman" as the password, which can then be used to decrypt the file

I can then decrypt the file and save it in the same folder:
$ ./pck_encrypt_decrypt.sh test/Philip_substack_cryptography.pdf.encf decf

Example 2 - encrypt a whole text file, then decrypt and only show the results in console

This command encrypts the whole text file in the test directory:
$ ./pck_encrypt_decrypt.sh test/internet_and_software_evolution.txt encf

The output is saved as a new file nternet_and_software_evolution.txt.encf
I also used "ironman" as the password.

I then decrypt it but have the results display on the console. In other words, it does not save the decrypted file into the filesystem:
$ ./pck_encrypt_decrypt.sh test/internet_and_software_evolution.txt.encf dec

Example 3 - encrypt partial of a text file, then decrypt the same section in console

This command encrypts the line in the text file that is enclosed in <enc-01></enc-01> tag:
$ ./pck_encrypt_decrypt.sh test/text_partial_encryption.txt encf enc-01

I used "qweRTY22" as the password.

I then decrypt the same line and have the results display on console:
$ ./pck_encrypt_decrypt.sh test/text_partial_encryption.txt.encf dec enc-01

The console displays this one line:
RESULTS: [<enc-01>qUicKBrownFox134</enc-01>]

Futhermore, for the last example, since there are multiple and different tags to be encrypted, I need to piggyback running the command, i.e.:
$ ./pck_encrypt_decrypt.sh test/text_partial_encryption.txt encf enc-01
$ ./pck_encrypt_decrypt.sh test/text_partial_encryption.txt.encf encf enc-02
$ ./pck_encrypt_decrypt.sh test/text_partial_encryption.txt.encf.encf encf enc-04

which I can then simplify the filename by replacing the first one with the last one, I can then remove the intermediate ones too:
$ mv test/text_partial_encryption.txt.encf.encf.encf test/text_partial_encryption.txt.encf

I used the same encryption password, which is "qweRTY22", to encrypt all 3 lines.

To decrypt and only show the results of one of the tag, i.e. 
$ ./pck_encrypt_decrypt.sh test/text_partial_encryption.txt.encf dec enc-02

The console displays this one line:
RESULTS: [<enc-02>passworD3322</enc-02>]