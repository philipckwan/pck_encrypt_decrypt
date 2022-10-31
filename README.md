PCK Encrypt Decrypt
=

PCK Encrypt Decrypt is an encryption and decryption tool.<br/>
It supports both Linux as a shell script, and Windows as a powershell script.<br/>
It can encrypt and decrypt any data files.<br/>
It can also encrypt and decrypt part of a text file.<br/>
That means, you can have a text file where only certain parts of it are encrypted.<br/>

Features
-

This tool:
* can encrypt and decrypt data in 3 methods:<br/>
(1) as a whole file<br/>
(2) given a plaintext file, only encrypt a segment of it.<br/>
(3) interactive mode, where you are prompted for the text to be encrypted or decrypted.<br/>
* the results of the encryption and decryption can be outputted in 3 ways:<br/>
(1) as a file, which means it will be saved on the computer.<br/>
(2) display on the terminal, which means it only stays in the computer memory and not being saved as a file.<br/>
(3) copy to the clipboard (i.e. like using Ctrl-C to copy and paste), which means not only it stays in the computer memory, but it also won't be shown on the terminal.
* have user provides a passphrase when performing the encryption. User will need to provide the same passphrase when performing the decryption.
* allows the encryption strength to be set between 1 (lowest) to 9 (highest). The higher the encryption strength, the more difficult it is to decrypt by brute force guessing the passphrase.

Command Arguments
-

Note: To run this tool in Windows, execute the Windows version of the script in a powershell terminal:<br/>
```win_pck_encrypt_decrypt.ps1```<br/>
The rest of the command line syntax is the same as the Linux shell version.<br/>

Key Example
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

I run the tool like this:
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

To decrypt the text and show it in the terminal only (i.e. not saving to a new file).<br/>
I will run the tool like this:
```
$ ./pck_encrypt_decrypt.sh test/t01-text-tag_key_within_line.txt.encf dec enc-01
...
Please enter the password: (input "qazWSX468" here)
...
-----RESULTS START-----
<enc-01>12345abcde 00000</enc-01>
-----RESULTS END-----
```

The results is successfully decrypted to the original text.<br/>

There are more examples of usage located in the "test" folder.<br/>
You may look into them and follow their instructions to try and get more understanding of the capability of this tool.

Command arguments and options
-

There are 2 ways to run this tool:<br/>
(1) filepath based<br/>
(2) interactive based<br/>

This is the filepath based syntax:
```
pck_encrypt_decrypt.sh <filepath> <encrypt option> [<tag keys>]
win_pck_encrypt_decrypt.ps1 <filepath> <encrypt option> [<tag keys>]
```
* filepath: relative path and filename, pointing to the file to be encrypt/decrypt.<br/>
If the filepath is a directory, it will process all the files under this directory<br/>
* encrypt option: The encryption and decryption option is one of the following:<br/>
enc - encrypt in memory, displaying the results in console <br/>
dec - decrypt in memory, displaying the results in console <br/>
encf - encrypt and output the results to a new file <br/>
decf - decrypt and output the results to a new file <br/>
* tag keys: < and > will be added to enclose tag key; i.e. pck-01 becomes \<pck-01> and \</pck-01> <br/>
It is expected the tag is enlosed like xml tags, i.e. \<pck-01> and \</pck-01> enclosed the inline text to be encrypted <br/>
If \<tag key> is not provided, it will assume the whole file needs to be encrypted/decrypted <br/>
tag keys can be a comma separated list, i.e. pck-01,pck-02,pck-04 will results in handling three tags \<pck-01>, \<pck-02> and \<pck-04>

This is the interactive based syntax:
```
pck_encrypt_decrypt.sh <encrypt option>
```
* encrypt option: The encryption and decryption option is one of the following:<br/>
enci - encrypt by first prompting for the text to be encrypted. The results will be displayed on console.<br/>
deci - decrypt by first prompting for the text to be decrypted. The results will be displayed on console.<br/>
decic - decrypt by first prompting for the text to be decrypted. The results will be copied to clipboard.<br/>

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

Change Log
-
Please refer to CHANGELOG for more details on the update and fix histories of this tool.
