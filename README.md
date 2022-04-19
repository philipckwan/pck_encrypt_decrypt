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
```
pck_encrypt_decrypt.sh <filepath> <encrypt option> [<tag keys>]
```
* filepath: relative path and filename, pointing to the file
* encrypt option: enc | dec | encf | decf <br/>
enc - encrypt in memory, showing the results in console <br/>
dec - decrypt in memory, showing the results in console <br/>
encf - encrypt and output to file <br/>
decf - decrypt and output to file <br/>
* tag keys: < and > will be added to enclose tag key; i.e. pck-01 becomes \<pck-01> and \</pck-01> <br/>
It is expected the tag is enlosed like xml tags, i.e. \<pck-01> and \</pck-01> enclosed the inline text to be encrypted <br/>
If \<tag key> is not provided, it will assume the whole file needs to be encrypted/decrypted <br/>
tag keys can be a comma separated list, i.e. pck-01,pck-02,pck-04 will results in handling three tags <pck-01>, <pck-02> and <pck-04>
* password will then be asked during the process of the script execution. <br/>

Examples
-

Example 1 - encrypt a whole binary file

This command encrypts the whole pdf file in the test directory:<br/>
```$ ./pck_encrypt_decrypt.sh test/Philip_substack_cryptography.pdf encf ```

The output is saved as a new file Philip_substack_cryptography.pdf.encf in the same folder.<br/>
I entered `ironman` as the password, which can then be used to decrypt the file

I can then decrypt the file and save it in the same folder:<br/>
```$ ./pck_encrypt_decrypt.sh test/Philip_substack_cryptography.pdf.encf decf```

Example 2 - encrypt a whole text file, then decrypt and only show the results in console

This command encrypts the whole text file in the test directory:<br/>
```$ ./pck_encrypt_decrypt.sh test/internet_and_software_evolution.txt encf```

The output is saved as a new file nternet_and_software_evolution.txt.encf<br/>
I also used `ironman` as the password.

I then decrypt it but have the results display on the console. In other words, it does not save the decrypted file into the filesystem:<br/>
```$ ./pck_encrypt_decrypt.sh test/internet_and_software_evolution.txt.encf dec```

Example 3 - encrypt partial of a text file, then decrypt the same section in console

This command encrypts the line in the text file that is enclosed in <enc-01></enc-01> tag:<br/>
```$ ./pck_encrypt_decrypt.sh test/text_partial_encryption.txt encf enc-01```

I used `qweRTY22` as the password.

The resulting file will be all identical to the orginal file except the line where the tag is enclosed.<br/>
It is changed from:<br/>
```<enc-01>qUicKBrownFox134</enc-01>```<br/>
to:<br/>
```<enc-01>27-A44iKZlfAuOWzs0nHghb+cx=</enc-01>```

I then decrypt the same line and have the results display on console:<br/>
```$ ./pck_encrypt_decrypt.sh test/text_partial_encryption.txt.encf dec enc-01```

The console displays this one line:<br/>
```RESULTS: [<enc-01>qUicKBrownFox134</enc-01>]```

Futhermore, for the last example, since there are multiple and different tags to be encrypted, I can put all keys in a comma-separated list:
```
$ ./pck_encrypt_decrypt.sh test/text_partial_encryption.txt encf enc-01,enc-02,enc-04
```

I used the same encryption password, which is `qweRTY22`, to encrypt all 3 lines.

To decrypt and only show the results of one or more of the tag, i.e. <br/>
```$ ./pck_encrypt_decrypt.sh test/text_partial_encryption.txt.encf dec enc-02,enc-04```

The console displays this one line:<br/>
```RESULTS: [<enc-02>passworD3322</enc-02>]```

Example 4 - encrypting the same text results in different output because of salt

In text_multiple_tags_with_salt, multiple lines are identical (i.e. they are "helloworld" or "ok")
But the resulting encrypted tags are different, because salt is being applied to the encryption process.
When salt is applied, the encrypted tag contect will contains a prefix of "xx-" where xx are 2 numbers
These 2 numbers are salt used to generated different output when encrypting.
But when decrypting, given the salt is provided and the same password is used, it will be able to recover back to the original text.
See <https://en.wikipedia.org/wiki/Salt_(cryptography)>

Try decrypt this file, with the password `qweRTY22`, to see.
```$ ./pck_encrypt_decrypt.sh test/text_multiple_tags_with_salt.txt.encf decf enc-01,enc-02,enc-03,enc-04```

Cryptography analysis and rational of this tool
-

I am not an expert in cryptography, but I do know at a high level about some common cryptography concepts such as public and private key (RSA) cryptography.<br/>
Base64 is not an encryption tool, it is only an encoding tool. That means it can be decoded back to the original source, without the need of any password, secret or key.<br/>
But what I have done in this tool is to first use Base64 to encode the original content, whether it is binary data or text.<br/>
Then, given the Base64 character set are 64 alpha, numeric and some symbols, what I did next is to shuffle the characters.<br/>
The shuffling is based on a user input password, where it deterministically/algorithmically generates a shuffling sequence.<br/>
Then the Base64 encoded content will be based on this sequence to shuffle.<br/>
When decrypting the content, if the user input password matches with the encryption, the same sequence will be generating and the shuffling can be reverse.<br/>
As I am not a cryptography experts, and I welcome any security and cryptography experts to help anaylze my algorithm.<br/>
For example, please do let me know if this algorithm can be easily hacked.

I see this tool have the following advantage, as compared to using other means of encryption, such as the password protect mechanism in Microsoft Office products, Openssl encryption, etc...
* because it is relying on common Linux tools such as base64, rev, tr, it can be independent from my script, meaning that one can use the same linux commands to decrypt it. It means a sense of portability, and less reliant on proprietary technology (i.e. Microsoft Word)
* I assume similar algorithm and commands can be replicated in a Windows environment too, in which I should put such items to a TODO list, i.e. to help come up with the same command or scripts in Windows power shell
* Since this tool can partially encrypt text file based on xml like tag enclosing the content, I personally see the use of this tool to encrypt my always growing list of web access username and passwords.<br/> 
The web access and username parts can be left unencrypted, with only the password part to be encrypted.<br/> 
And when decrypting, I don't have to decrypt the whole file but just decrypt only the line that I want.<br/> 
If setting different password for different tags, then the whole text file can be accessed with different passwords.

The Base64 charset shuffling
-

Details of this shuffling can be found in the script. But just to provide here in a nutshell.<br/>
```base64_charset="/+9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"```<br/>
Then, given a user provided encryption password such as `qweRTY22`, it is inserted to the front, and the whole sequence is shift to the right.<br/>
Repeated character will be removed to keep the sequence to have a constant length of 64.<br/>
The resulting sequence is thus:<br/>
```base64_charset="qweRTY2/+987654310ZXWVUSQPONMLKJIHGFEDCBAzyxvutsrponmlkjihgfdcba"```<br/>
Then, a reverse of the sequence is produced:<br/>
```base64_reverse="abcdfghijklmnoprstuvxyzABCDEFGHIJKLMNOPQSUVWXZ013456789+/2YTRewq"```<br/>
and it will be used along with the linux command `tr` to replace the Base64 encoded content:<br/>
```echo $content | $TR "${base64_charset}" "${base64_reverse}```<br/>
The entropy of such shuffling, should be depended on the length of the user input password.<br/>
In other words, the longer it is, the less repeating character it contains, the more unique character it contains, will result in a more deviated sequence than the original base64 character set, which should therefore results in a more secure shuffled contents than the original Base64 encoded contents.
