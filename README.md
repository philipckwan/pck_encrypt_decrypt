PCK Encrypt Decrypt
=

PCK Encrypt Decrypt is an encryption and decryption tool.<br/>
It supports (1) Linux as a shell script, (2) Windows as a powershell script, and (3) has a Chrome Extension to run on web browser. <br/>
It can encrypt and decrypt part of a text file.<br/>
That means, you can have a text file where only certain parts of it are encrypted.<br/>
And it can encrypt and decrypt files of any data (i.e. image, video, pdf) too.<br/>

Features
-

This tool:
* can encrypt and decrypt data in 3 methods:<br/>
(1) given a plaintext file, only encrypt parts of it.<br/>
(2) as a whole file<br/>
(3) interactive mode, where you are prompted for the text to be encrypted or decrypted.<br/>
* the results of the encryption and decryption can be outputted in 3 ways:<br/>
(1) as a file, which means it will be saved on the computer.<br/>
(2) display on the terminal/screen, which means it only stays in memory and not being saved to the computer hard disk.<br/>
(3) copy to the clipboard (i.e. like using Ctrl-C to copy and paste), which means not only it stays in the computer memory, but it also won't be shown on the computer screen.
* have user provides a passphrase when performing the encryption. User will need to provide the same passphrase when performing the decryption.
* allows the encryption strength to be set between 1 (lowest) to 9 (highest). The higher the encryption strength, the more difficult it is to decrypt by brute force guessing the passphrase.

Chrome Extensions and Windows version
-

The Chrome Extension version of this tool is located here:<br/>
https://github.com/philipckwan/pck_encrypt_decrypt/tree/main/ce-pck_encrypt_decrypt

For Windows, execute the Windows version of the script in a powershell terminal:<br/>
```win_pck_encrypt_decrypt.ps1```<br/>
The rest of the command line syntax is the same as the Linux shell version.<br/>

Examples
-
To showcase one of the major feature of this tool, here is the example of encrypting and decrypting a segment of a plaintext file.<br/>
Originally, I have a plaintext file:
```
test/t01-text-tag_key_within_line.txt
```
Its content contains a section like this:
```
#1 - full line with tag key, results should be: 
<xxxxxx>12345abcde 00000</xxxxxx>
<enc-01>12345abcde 00000</enc-01>
```

I want to encrypt the text that is enclosed between the tags \<enc-01> and \</enc-01>:
```
12345abcde 00000
```
with a passphrase:
```
qazWSX468
```

I run the tool like this, using ```encf``` as the option to encrypt and save to a file:
```
$ ./pck_encrypt_decrypt.sh test/t01-text-tag_key_within_line.txt encf enc-01
...
Please enter the password: (input "qazWSX468" here)
Please re-enter the password: (input "qazWSX468" here again)
...
```

After the tools is ran, I got a new file:
```
test/t01-text-tag_key_within_line.txt.encf
```
where the section now looks like this:
```
#1 - full line with tag key, results should be: 
<xxxxxx>12345abcde 00000</xxxxxx>
<enc-01>932-+fEgrQAx7CTP4SAl8CZupS+xXUjfXVycF5==</enc-01>
```

The results is the text between the tags \<enc-01> and \</enc-01> are now encrypted.<br/>
```932-+fEgrQAx7CTP4SAl8CZupS+xXUjfXVycF5==```<br/>

To decrypt the text and show it in the terminal only (i.e. not saving to a new file).<br/>
I will run the tool like this, using ```dec``` as the option:
```
$ ./pck_encrypt_decrypt.sh test/t01-text-tag_key_within_line.txt.encf dec enc-01
...
Please enter the password: (input "qazWSX468" here)
...
-----RESULTS START-----
<enc-01>12345abcde 00000</enc-01>
-----RESULTS END-----
```
The results is successfully decrypted to the original text, and displayed on the console.<br/>

You may also decrypt the text with the interactive mode, with ```deci``` as the option<br/>
You can copy and pasted the encrypted text when the tool prompts for it:<br/>
```
$ ./pck_encrypt_decrypt.sh deci 
...
Please type or paste the encrypted text: 932-+fEgrQAx7CTP4SAl8CZupS+xXUjfXVycF5==
Please enter the password: (input "qazWSX468" here)
12345abcde 00000

```

There are more examples of usage located in the ```test``` folder.<br/>
You may look into them and follow their instructions to try and get more understanding of the capability of this tool.

Running this tool
-

There are 2 ways to run this tool:<br/>
(1) filepath based<br/>
(2) interactive based<br/>

Filepath based
-
This is the filepath based syntax:
```
pck_encrypt_decrypt.sh <filepath> <encrypt option> [<tag keys>]
win_pck_encrypt_decrypt.ps1 <filepath> <encrypt option> [<tag keys>]
```
* filepath: relative path and filename, pointing to the file to be encrypt/decrypt.<br/>
If the filepath is a directory, it will process all the files under this directory<br/>
* encrypt option: The encryption and decryption option is one of the following:<br/>
```enc``` - encrypt in memory, displaying the results in console <br/>
```dec``` - decrypt in memory, displaying the results in console <br/>
```encf``` - encrypt and output the results to a new file <br/>
```decf``` - decrypt and output the results to a new file <br/>
* tag keys: < and > will be added to enclose tag key; i.e. pck-01 becomes \<pck-01> and \</pck-01> <br/>
It is expected the tag is enlosed like xml tags, i.e. \<pck-01> and \</pck-01> enclosed the inline text to be encrypted <br/>
If \<tag key> is not provided, it will assume the whole file needs to be encrypted/decrypted <br/>
tag keys can be a comma separated list, i.e. pck-01,pck-02,pck-04 will results in handling three tags \<pck-01>, \<pck-02> and \<pck-04>
* encryption option with the encryption strength<br/>
For encryption, the encryption strength can be optionally added to the end of the encryption option.<br/>
Given the encrption option:<br/>
```encf```<br/>
If you want to encryption with maximum strength of "9", you can specify it as:<br/>
```encf9```<br/>
As in this example:<br/>
```./pck_encrypt_decrypt.sh test/t01-text-tag_key_within_line.txt encf9 enc-01```<br/>
The default encryption strength is currently set at "2".<br/>
A higher encryption option will make the encrypted text longer, this will cause the text to be less likely to be decrypted by brute force, or keep guessing on the passphrase.
* decrypt and copy to clipboard<br/>
```decc```<br/>
Use this mode to decrypt from file with tags, where the first matched decrypted will be copied to clipboard.<br/>
As in this example:<br/>
```./pck_encrypt_decrypt.sh test/t09-text-decc.txt decc en.2```<br/>
* decrypt and strip the last file extension<br/>
```decfs```<br/>
For mode "decf" decryption of a whole file, in the general case it will append the extension ".decf" to the decrypted file.<br/>
But for this mode, instead it will strip the last file extension of the original encrypted file.<br/>
This is useful for it reverse the operation that when one uses the mode "encf" to encrypt the file, it appends the ".encf" extension.<br/>
Using this mode to decrypt will get you back to the filename when you originally encrypted it.<br/>
* decrypt a file and put it onto ramdisk<br/>
```decfr```<br/>
This mode will put the decrypted file onto a newly created ramdisk<br/>
My idea of using this mode is to prevent the decrypted file to be written to the file system.<br/>
After using the decrypted file, the user should unmount and eject the ramdisk<br/>
This mode also assumes the "decfs" option and will strip the ".encf" extension<br/>

Interactive based
-
This is the interactive based syntax:

```
pck_encrypt_decrypt.sh <encrypt option>
```
* encrypt option: The encryption and decryption option is one of the following:<br/>
```enci``` - encrypt by first prompting for the text to be encrypted. The results will be displayed on console.<br/>
```deci``` - decrypt by first prompting for the text to be decrypted. The results will be displayed on console.<br/>
```encic``` - encrypt by first prompting for the text to be encrypted. The results will be copied to clipboard.<br/>
```decic``` - decrypt by first prompting for the text to be decrypted. The results will be copied to clipboard.<br/>
The encryption strength option is also supported in these interactive modes.
For example, you may run the tool to encrypt a text with strength of "5" like this:<br/>
```
$ ./pck_encrypt_decrypt.sh enci5
...
Please type or paste the encrypted text: hello
Please enter the password: (input a passphrase here)
Please re-enter the password: (input the same passphrase here)
555-WlCyjkZThifTk2Ofaa2MZMAxreOcYif3YaT2ZS3=
```

Cryptography analysis and rationale of this tool
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
* Since this tool can partially encrypt text file based on xml like tag enclosing the content, I personally see the use of this tool to encrypt my always growing list of web access username and passwords.<br/> 
The web access and username parts can be left unencrypted, with only the password part to be encrypted.<br/> 
And when decrypting, I don't have to decrypt the whole file but just decrypt only the line that I want.<br/> 
If setting different password for different tags, then the whole text file can be accessed with different passwords.

The Base64 character set shuffling
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
In other words, the longer it is, the less repeating character it contains, the more unique character it contains, will result in a more deviated sequence than the original base64 character set, which should therefore results in a more secure shuffled contents than the original Base64 encoded contents.<br/>
Due to the nature of generating this Base64 character set, the repeating characters of a password do not cause further deviated sequence of this Base64 sequence.<br/>
But with the alpha-numeric character set shuffling (see section below), repeat characters of a password can be used to shuffle the resulting text, making the results more difficult to be decrypted.<br/>

The alpha-numeric character set shuffling
-

Since version v1.11, the tool introduced an extra text shuffling, the alpha-numeric characters shuffling.<br/>
The password from the user will be used to further generate a text shuffling sequence.<br/>
```text_shuffle_charset="0123456789 abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"```<br/>
In particular, the duplicated characters of the password are used to generate this text shuffling sequence.<br/>
For encryption, before applying the Base64 character set shuffling, the text first goes through this alpha-numeric shuffling.<br/>
Then, the Base64 character shuffling and encryption will be applied.<br/>
For decryption, after the Base64 character decryption is applied, the text will go through the alpha-numeric shuffling again.<br/>
The end result is that, in addition to the Base64 character set encryption, the resulting text will also have an extra text shuffling provided by the alpha-numeric character shuffling.<br/>
For password encryption, this could be useful in that even if the text can be decrypted by the Base64 character encryption from passwords that has duplicate characters, the text shuffling will still make it difficult to be decrypted.<br/>
As this alpha-numeric character set only contains alphabets and numbers, this shuffling cannot be applied to other characters, such as Chinese characters.<br/>

Change Log
-
Please refer to CHANGELOG for more details on the update and fix history of this tool.
