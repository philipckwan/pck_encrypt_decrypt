PCK Encrypt Decrypt (Chrome Extension)
=

This folder contains the Chrome Extension of PCK Encrypt Decrypt.<br/>

If you want to install this Chrome Extension directly from this repository, you will have to use the "Load Unpack" function.
Please see the instructions below:<br/>
https://developer.chrome.com/docs/extensions/mv3/getstarted/development-basics/#load-unpacked

Installation
-

Here is a short summary:<br/>
1) Download this project (i.e. as a zip file) and unzip it. Or, you may use Git command "git clone" to clone this project<br/>
2) Locate the Chrome Extension folder, which is this folder "ce-pck_encrypt_decrypt". This will be the directory to load to Chrome Extension<br/>
3) Open Chrome, go to "chrome://extensions"<br/>
4) Enable Developer Mode<br/>
5) Click on "Load Unpack" and select this folder "ce-pck_encrypt_decrypt"<br/>

Usage
-

Once the Chrome extension is installed, you may use it by the following procedures:<br/>
1) From your browser, click and highlight a piece of text that you want to encrypt<br/>
2) Right click to open the context menu, you will see the "PCK Encrypt Decrypt" menu item.<br/>
3) Hover the mouse to it, and it will bring up 3 sub menu items:<br/>
* Encrypt (clipboard) - this will bring up the password prompt dialog, you will enter the password twice to confirm the encryption<br/>
* Decrypt (clipboard) - this will bring up the password prompt dialog, you will enter the password once to decrypt<br/>
* Launch app - this will launch a sepearate page where you can freely enter text and password to encrypt and decrypt<br/>

Encrypt
-

First select the text to be encrypted, then launch the "Encrypt (clipboard)" menu item.<br/><br/>
<img width="600" alt="image" src="https://user-images.githubusercontent.com/11599040/226792338-834f3e51-33a8-47d4-9e37-25ed80e81cfb.png">
<br/><br/>
Enter the password twice to confirm the encryption.<br/><br/>
<img width="600" alt="image" src="https://user-images.githubusercontent.com/11599040/226792050-7aadca50-393c-4a42-987f-5c9b4dd27d6f.png">
<br/><br/>
Upon successful encryption, the results will be saved to the clipboard. You may paste it out to check<br/><br/>
<img width="1000" alt="image" src="https://user-images.githubusercontent.com/11599040/226792568-e48aa03a-022f-4d37-9d87-4adb89bf0eb7.png">

Decrypt
-

First select the text to be decrypt, then launch the "Decrypt (clipboard)" menu item.<br/><br/>
<img width="600" alt="image" src="https://user-images.githubusercontent.com/11599040/226793651-7d70adc6-feb6-4b11-8fd3-ebdae8d6d514.png">
<br/><br/>
Enter the password to confirm the decryption.<br/><br/>
<img width="600" alt="image" src="https://user-images.githubusercontent.com/11599040/226794061-01748f45-bb39-40bf-9aac-3618e7e1e504.png">
<br/><br/>
Upon successful decryption, the results will be saved to the clipboard. You may paste it out to check<br/><br/>
<img width="600" alt="image" src="https://user-images.githubusercontent.com/11599040/226794323-417c3be6-e9d1-4eea-ae37-903a0eb8dd65.png">
<br/><br/>

Launch app
-
Launching the app provides more flexibility for you to freely input text to encrypt and decrypt.<br/><br/>
<img width="800" alt="image" src="https://user-images.githubusercontent.com/11599040/226794645-f014a4b0-accb-4343-b004-1c8ef3d9131d.png">
<br/><br/>
At the app, you are free to encrypt and decrypt text, swap the input and results.<br/>
You may also select the encryption security, from 1 the lowest, to 9 the highest. Default is 5.<br/><br/>
<img width="600" alt="image" src="https://user-images.githubusercontent.com/11599040/226794918-2f3c6f32-cb5c-435d-966a-3cdc06068f20.png">
<br/><br/>


