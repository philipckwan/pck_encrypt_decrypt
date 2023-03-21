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

document.addEventListener('submit', e => {
  timeLog(`index.js.submit: 1.1;`);
  e.preventDefault();
  const inputText = document.getElementById('inputTextArea').value;
  const password = document.getElementById('password').value;
  const operation = e.target.dataset.action;

  timeLog(`index.js.submit: inputText:[${inputText}]; password:[${password}]; operation:[${operation}]`);

  let outputText = "";
  let errorOneLine = "";
  if (operation === "encrypt") {
    const encryptRounds = document.getElementById('encryptRounds').value;
    timeLog(`__encryptRounds:[${encryptRounds}]`);
    [outputText, errorOneLine] = encryptOneLine(inputText, password, encryptRounds);
  } else {
    [outputText, errorOneLine] = decryptOneLine(inputText, password);
  }
  const outputTextArea = document.getElementById('outputTextArea');

  timeLog(`__outputText: [${outputText}]; errorOneLine:[${errorOneLine}];`);

  if (errorOneLine != "") {
    outputTextArea.value = `!!!${errorOneLine}!!!`;
  } else {
    outputTextArea.value = outputText;
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
