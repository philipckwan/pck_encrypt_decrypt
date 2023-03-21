import {Base64} from './base64.js';
import {timeLog} from "./commons.js"

const base64Charset="/+9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"
const textShuffleCharset="0123456789 abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

const textShuffleVersionSupported = 1;
const SALT_SEPARATOR = "-";

export async function askPassword(isEncrypt, tabId) {
  timeLog(`pck_encrypt_decrypt.askPassword: isEncrypt:[${isEncrypt}]; tabId:[${tabId}]`);
  let passwordAfterPrompt = "";
  let errorOneLine = "";
  try {
    const r = await chrome.scripting.executeScript({
      args: [isEncrypt],
      target: {
        tabId: tabId
      },
      func: (isEncrypt) => {
        const passwordValidCharset="9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba";
        const passwordEntered = prompt(`Enter a password`);
        if (passwordEntered.length < 3) {
          return {error: 'ERROR - password must be at least 3 characters long.'};
        }
        for (let i = 0; i < passwordEntered.length; i++) {
          if (!passwordValidCharset.includes(passwordEntered[i])) {
            return {error: 'ERROR - password contains invalid character(s). Please only input alphanumeric characters for password.'};
          }
        }
        if (isEncrypt) {
          const passwordConfirm = prompt(`Re-enter the password`);
          if (passwordEntered !== passwordConfirm) {
            return {error: 'ERROR - Passwords do not match. Operation terminated'};
          }
        }
        window.focus();
        return {
          password: passwordEntered
        };
      }
    });
    let theResult = r[0].result;
    if (theResult.error) {
      errorOneLine = theResult.error;
    }
    passwordAfterPrompt = theResult.password;
  }
  catch (e) {
    errorOneLine = e.message;
  }
  return [passwordAfterPrompt, errorOneLine];
}

export function extractHeaderFromEncryptedText(text) {
  //timeLog(`extractHeaderFromEncryptedText: text:[${text}]`)
  let errorOneLine = "";
  let headerVersion = 1;
  let saltNumRepeat = 0;
  let saltShuffleIdx = 0;
  let encryptDecryptRounds = 1;
  let textShuffleVersion = 0;
  if (text.substring(2,3) === SALT_SEPARATOR) {
    headerVersion = 2;
    saltNumRepeat = parseInt(text.substring(0,1));
    saltShuffleIdx = parseInt(text.substring(1,2));
    encryptDecryptRounds = 1;
  } else if (text.substring(3,4) === SALT_SEPARATOR) {
    headerVersion = 3;
    saltNumRepeat = parseInt(text.substring(0,1));
    saltShuffleIdx = parseInt(text.substring(1,2));
    encryptDecryptRounds = parseInt(text.substring(2,3));
  } else if (text.substring(4,5) === SALT_SEPARATOR) {
    headerVersion = 4;
    saltNumRepeat = parseInt(text.substring(0,1));
    saltShuffleIdx = parseInt(text.substring(1,2));
    encryptDecryptRounds = parseInt(text.substring(2,3));
    textShuffleVersion = parseInt(text.substring(3,4));
    if (textShuffleVersion != textShuffleVersionSupported) {
      errorOneLine = `ERROR - invalid text_shuffle_version [${textShuffleVersion}]`;
    }
  } else {
    errorOneLine = `ERROR - header is not found`;
  }
  return [headerVersion, saltNumRepeat, saltShuffleIdx, encryptDecryptRounds, textShuffleVersion, errorOneLine];
}

export function passwordProcess(passwordFromStdin, isEncrypt, saltNumRepeat = 0, saltShuffleIdx = 0) {
	// obtain the password_removed_dups, dup_char_array and dup_count_array
	// dup_char_array and dup_count_array are for text shuffle
  let passwordRemovedDups=""
  let dupCharArray=[];
  let dupCountArray=[];

  for (let i = 0; i < passwordFromStdin.length; i++) {
    let thisChar = passwordFromStdin[i];
    if (!passwordRemovedDups.includes(thisChar)) {
      passwordRemovedDups+=thisChar;
    } else {
      dupCharArray.push(thisChar);
      dupCountArray.push(i);
    }
  }

  let textShuffleCharsetProcessed = textShuffleCharset;
  for (let i = 0; i < dupCharArray.length; i++) {
    let thisLetter = dupCharArray[i];
    let thisNumber = dupCountArray[i];
    let combinedCharset = thisLetter+textShuffleCharsetProcessed;
    let charsetProcessed = "";
    for (let j = 0; j < combinedCharset.length; j++) {
      let thisChar = combinedCharset[j];
      if (!charsetProcessed.includes(thisChar)) {
        charsetProcessed += thisChar;
      }
    }
    let charsetMoveToHead = charsetProcessed.substring(charsetProcessed.length - thisNumber);
    let charsetTail = charsetProcessed.substring(0, charsetProcessed.length - thisNumber);
    charsetProcessed = charsetMoveToHead + charsetTail;
    textShuffleCharsetProcessed = charsetProcessed;
  }

  // if encrypt and tag based
	//  generate $salt_num_repeat and $salt_shuffle_idx,then apply to $password_processed and $password_reversed
	// if decrypt and tag based
	//  take from $salt_num_repeat and $salt_shuffle_idx, then apply to $password_processed and $password_reversed
	// if not tag based (i.e. whole file encrypt/decrypt)
	//  salt is not supported for this type
  let combinedPasswordBase64Charset = passwordRemovedDups + base64Charset;
  let passwordProcessed = ""
  for (let i = 0; i < combinedPasswordBase64Charset.length; i++) {
    let thisChar = combinedPasswordBase64Charset[i];
    if (!passwordProcessed.includes(thisChar)) {
      passwordProcessed += thisChar;
    }
  }

  if (isEncrypt) {
    saltNumRepeat = Math.floor(Math.random() * 9) + 1;
    saltShuffleIdx = Math.floor(Math.random() * 9) + 1;
  }

  if (saltNumRepeat > 0) {
    for (let i = 0; i < saltNumRepeat; i++) {
      let pwdSalt = passwordProcessed.substring(passwordProcessed.length - saltShuffleIdx).split("").reverse().join("");
      let pwdHead = passwordProcessed.substring(0, passwordProcessed.length - saltShuffleIdx);
      passwordProcessed = pwdSalt + pwdHead;
    }
  }
  return [textShuffleCharsetProcessed, passwordProcessed, saltNumRepeat, saltShuffleIdx];
}

export function encryptOneLine(inputText, password, encryptDecryptRounds = 5) {
  //timeLog(`encryptOneLine: 1.0; encryptDecryptRounds:[${encryptDecryptRounds}]`)
  let resultText = "";
  let errorOneLine = "";

  let [textShuffleCharsetProcessed, passwordProcessed, saltNumRepeat, saltShuffleIdx] = passwordProcess(password, true);
  //timeLog(`encryptOneLine: textShuffleCharsetProcessed:[${textShuffleCharsetProcessed}]; passwordProcessed:[${passwordProcessed}]`);
  //timeLog(`encryptOneLine: saltNumRepeat:[${saltNumRepeat}]; saltShuffleIdx:[${saltShuffleIdx}]`);

  // TODO: hardcode for now, need to revisit
  //let encryptDecryptRounds = 5;

  // first, perform the text shuffle
  let textShuffleMap = new Map();
  for (let i = 0; i < textShuffleCharsetProcessed.length; i++) {
    textShuffleMap.set(textShuffleCharsetProcessed[i], textShuffleCharsetProcessed[textShuffleCharsetProcessed.length - 1 - i]);
  }
  for (let i = 0; i < inputText.length; i++) {
    if (textShuffleMap.get(inputText[i]) == undefined) {
      resultText += inputText[i];
    } else {
      resultText += textShuffleMap.get(inputText[i]);
    }
  }
  //timeLog(`__textShuffleCharsetProcessed:[${textShuffleCharsetProcessed}]`);
  //timeLog(`__textShuffleCharsetReversed: [${textShuffleCharsetProcessed.split("").reverse().join("")}]`)
  //timeLog(`__inputText: [${inputText}]`)
  //timeLog(`__resultText:[${resultText}]`);

  // next, do the looping of base64 encode and password shuffle
  let passwordShuffleMap = new Map();
  for (let i = 0; i < passwordProcessed.length; i++) {
    passwordShuffleMap.set(passwordProcessed[i], passwordProcessed[passwordProcessed.length - 1 - i]);
  }
  for (let i = 0; i < encryptDecryptRounds; i++) {
    let base64Encoded = Base64.encode(resultText);
    let passwordShuffled = "";
    for (let j = 0; j < base64Encoded.length; j++) {
      if (passwordShuffleMap.get(base64Encoded[j]) == undefined) {
        passwordShuffled += base64Encoded[j];
      } else {
        passwordShuffled += passwordShuffleMap.get(base64Encoded[j]);
      }
    }    
    resultText = passwordShuffled;
  }
  resultText = `${saltNumRepeat}${saltShuffleIdx}${encryptDecryptRounds}${textShuffleVersionSupported}${SALT_SEPARATOR}${resultText}`;

  return [resultText, errorOneLine];
}

export function decryptOneLine(inputText, password) {
  let errorOneLine = "";
  let inputOneLineHeaderStripped = "";
  let outputOneLine = "";
  let [headerVersion, saltNumRepeat, saltShuffleIdx, encryptDecryptRounds, textShuffleVersion, errorOneLineFromExtract] = extractHeaderFromEncryptedText(inputText);
  if (errorOneLineFromExtract != "") {
    return [outputOneLine, errorOneLineFromExtract];
  }

  if (headerVersion === 2) {
    inputOneLineHeaderStripped = inputText.substring(3);
  } else if (headerVersion === 3) {
    inputOneLineHeaderStripped = inputText.substring(4);
  } else if (headerVersion === 4) {
    inputOneLineHeaderStripped = inputText.substring(5);
  }
  let [textShuffleCharsetProcessed, passwordProcessed, saltNumRepeatIgnored, saltShuffleIdxIgnored] = passwordProcess(password, false, saltNumRepeat, saltShuffleIdx);

  outputOneLine = inputOneLineHeaderStripped;
  let passwordShuffleMap = new Map();
  for (let i = 0; i < passwordProcessed.length; i++) {
    passwordShuffleMap.set(passwordProcessed[i], passwordProcessed[passwordProcessed.length - 1 - i]);
  }
  for (let i = 0; i < encryptDecryptRounds; i++) {
    let passwordShuffled = "";
    for (let j = 0; j < outputOneLine.length; j++) {
      if (passwordShuffleMap.get(outputOneLine[j]) == undefined) {
        passwordShuffled += outputOneLine[j];
      } else {
        passwordShuffled += passwordShuffleMap.get(outputOneLine[j]);
      }
    }    
    try {
      outputOneLine = Base64.decode(passwordShuffled);
    } catch (ex) {
      errorOneLine = "ERROR - you might have entered a wrong password";
      return [outputOneLine, errorOneLine];
    }
  }
  // apply the text shuffle if header_version == 4
  if (headerVersion === 4) {
    if (textShuffleVersionSupported === 1) {
      let textShuffleMap = new Map();
      for (let i = 0; i < textShuffleCharsetProcessed.length; i++) {
        textShuffleMap.set(textShuffleCharsetProcessed[i], textShuffleCharsetProcessed[textShuffleCharsetProcessed.length - 1 - i]);
      }
      let textShuffled = "";
      for (let i = 0; i < outputOneLine.length; i++) {
        if (textShuffleMap.get(outputOneLine[i]) == undefined) {
          textShuffled += outputOneLine[i];
        } else {
          textShuffled += textShuffleMap.get(outputOneLine[i]);
        }
      }
      outputOneLine = textShuffled;
    } else {
      errorOneLine = `ERROR - invalid text_shuffle_version_supported: [${textShuffleVersionSupported}]`;
    }
  }
  if (outputOneLine == "") {
    errorOneLine = "ERROR - you might have entered a wrong password";
  }
  return [outputOneLine, errorOneLine];
}