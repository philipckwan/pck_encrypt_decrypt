import {timeLog} from "./commons.js"
import {askPassword, encryptOneLine, decryptOneLine} from "./pck_encrypt_decrypt.js"

async function launchApp(selectedText) {
  timeLog(`worker.launchApp: selectedText length:[${selectedText.length}]; excerpt:[${selectedText.substring(0,5)}...${selectedText.substring(selectedText.length-5)}]`);
  const win = await chrome.windows.getCurrent();
  chrome.windows.create({
    url: '/app/index.html?content=' + encodeURIComponent(selectedText),
    width: 700,
    height: 400,
    left: win.left + Math.round((win.width - 700) / 2),
    top: win.top + Math.round((win.height - 400) / 2),
    type: 'popup'
  })
  /*
  chrome.storage.local.get({
    width: 700,
    height: 400,
    left: win.left + Math.round((win.width - 700) / 2),
    top: win.top + Math.round((win.height - 400) / 2)
  }, prefs => {
    chrome.windows.create({
      url: '/app/index.html?content=' + encodeURIComponent(selectedText),
      width: prefs.width,
      height: prefs.height,
      left: prefs.left,
      top: prefs.top,
      type: 'popup'
    });
  });
  */
}

async function copyToClipboard(text, tabId) {
  //timeLog(`worker.copyToClipboard: 1.2: text:[${text}]`);
  let errorOneLine = "";
  
  await chrome.tabs.update(tabId, {
    highlighted: true
  });
  await new Promise(resolve => setTimeout(resolve, 500));
  
  let results = await chrome.scripting.executeScript({
    args: [text],
    target: {
      tabId
    },
    func: async (encrypted) => {
      try {
        await navigator.clipboard.writeText(encrypted);
      } catch (ex1) {
        return {error: ex1.message};
      }
      return "";
    }
  });
  let theResult = results[0].result;
  if (theResult.error) {
    errorOneLine = `ERROR [2] - Cannot copy to clipboard [${theResult.error}]`;
  } 
  return errorOneLine;
}



async function notifyError(message, tid) {
  //timeLog(`worker.notifyError: message:[${message}]`);
  console.warn(message);
  await chrome.scripting.executeScript({
    args: [message],
    target: {
      tabId: tid
    },
    func: (message) => {
      alert(message);
    }
  });
}

async function notify(message, tid) {
  //timeLog(`worker.notify: message:[${message}]`);
  await chrome.scripting.executeScript({
    args: [message],
    target: {
      tabId: tid
    },
    func: (message) => {
      alert(message);
    }
  });
}


// Context Menu
{
  const callback = () => {
    chrome.contextMenus.create({
      id: 'encrypt-clipboard',
      title: 'Encrypt (clipboard)',
      contexts: ['selection'],
      documentUrlPatterns: ['*://*/*']
    });
    chrome.contextMenus.create({
      id: 'decrypt-clipboard',
      title: 'Decrypt (clipboard)',
      contexts: ['selection'],
      documentUrlPatterns: ['*://*/*']
    });
    chrome.contextMenus.create({
      id: 'launch-app',
      title: 'Launch app',
      contexts: ['selection'],
      documentUrlPatterns: ['*://*/*']
    });
  };
  chrome.runtime.onInstalled.addListener(callback);
  chrome.runtime.onStartup.addListener(callback);
}

const onClicked = async (info, tab) => {
  //timeLog(`worker.onClicked: v0.4`);
  let method = info.menuItemId || '';
  let selectedText = info.selectionText;

  if (method === "launch-app") {
    launchApp(selectedText);
  } else {
    let isEncrypt = method.startsWith('encrypt-');

    let errorOneLine = "";
    let passwordFromPrompt = "";
    [passwordFromPrompt, errorOneLine] = await askPassword(isEncrypt, tab.id);
    if (errorOneLine != "") {
      return notifyError(errorOneLine, tab.id);
    }
    
    let outputText = "";
    if (!isEncrypt) {
      [outputText, errorOneLine] = decryptOneLine(selectedText, passwordFromPrompt);
    } else {
      [outputText, errorOneLine] = encryptOneLine(selectedText, passwordFromPrompt);
    }

    if (errorOneLine != "") {
      return notifyError(errorOneLine, tab.id);
    } else {
      errorOneLine = await copyToClipboard(outputText, tab.id);
      if (errorOneLine != "") {
        return notifyError(errorOneLine, tab.id);
      } else {
        return notify("Operation successful. Text is copied to clipboard.", tab.id);
      }
    }
  }
};
chrome.contextMenus.onClicked.addListener(onClicked);

chrome.action.onClicked.addListener(() => onClicked({
  menuItemId: 'launch-app',
  selectionText: ''
}));