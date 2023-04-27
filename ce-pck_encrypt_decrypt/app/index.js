/* globals safe */
'use strict';

import {timeLog} from "/commons.js";
import {encryptOneLine, decryptOneLine} from "/pck_encrypt_decrypt.js"
const args = new URLSearchParams(location.search);

if (args.has('content')) {
  let selectedText = args.get('content');
  timeLog(`index.js: selectedText length:[${selectedText.length}]; excerpt:[${selectedText.substring(0,5)}...${selectedText.substring(selectedText.length-5)}]`);
  document.getElementById('inputTextArea').value = selectedText;
}

document.getElementById('encrypt').addEventListener('click', () => {
  document.forms[0].dataset.action = 'encrypt';
});
document.getElementById('decrypt').addEventListener('click', () => {
  document.forms[0].dataset.action = 'decrypt';
});
document.getElementById('encrypt_clipboard').addEventListener('click', () => {
  document.forms[0].dataset.action = 'encrypt_clipboard';
});
document.getElementById('decrypt_clipboard').addEventListener('click', () => {
  document.forms[0].dataset.action = 'decrypt_clipboard';
});

document.addEventListener('submit', async e => {
  //timeLog(`index.js.submit: 1.1;`);
  e.preventDefault();
  const inputText = document.getElementById('inputTextArea').value;
  const password = document.getElementById('password').value;
  const operation = e.target.dataset.action;

  //timeLog(`index.js.submit: inputText:[${inputText}]; password:[${password}]; operation:[${operation}]`);

  let outputText = "";
  let errorOneLine = "";
  if (operation.startsWith("encrypt")) {
    const encryptRounds = document.getElementById('encryptRounds').value;
    //timeLog(`__encryptRounds:[${encryptRounds}]`);
    [outputText, errorOneLine] = encryptOneLine(inputText, password, encryptRounds);
  } else {
    [outputText, errorOneLine] = decryptOneLine(inputText, password);
  }
  const outputTextArea = document.getElementById('outputTextArea');

  //timeLog(`__outputText: [${outputText}]; errorOneLine:[${errorOneLine}];`);

  if (errorOneLine != "") {
    outputTextArea.value = `!!!${errorOneLine}!!!`;
  } else {
    if (operation.endsWith("clipboard")) {
      //timeLog(`__about to write to clipboard;`);
      let outputMsg = "";
      try {
        await navigator.clipboard.writeText(outputText);
        outputMsg = `(results copied to clipboard; length of text:${outputText.length}) (There is a known issue of having an extra space at the end of some decrypted text, please be aware)`;
      } catch (ex1) {
        outputMsg = `!!!ERROR - failed to write to clipboard!!!`;
        timeLog(`ERROR - failed to write to clipboard; ${ex1};`);
      }
      //timeLog(`__done writing to clipboard;`);
      outputTextArea.value = outputMsg;
    } else {
      outputTextArea.value = outputText;
    } 
  }

  /*
  if (safe[e.target.dataset.action]) {
    safe[e.target.dataset.action](data, password).then(s => result.value = s)
      .catch(e => result.value = e.message || 'Operation was unsuccessful');
  }
  */
});


document.getElementById('swap').onclick = () => {
  const v1 = document.getElementById('inputTextArea').value;
  const v2 = document.getElementById('outputTextArea').value;

  document.getElementById('inputTextArea').value = v2;
  document.getElementById('outputTextArea').value = v1;
};

document.getElementById('inputTextArea').oninput = () => {
  document.getElementById('outputTextArea').value = '';
};
