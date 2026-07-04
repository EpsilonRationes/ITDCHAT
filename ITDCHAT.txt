// ==UserScript==
// @name         ITD Chat
// @namespace    https://github.com/EpsilonRationes/ITDCHAT
// @version      0.2
// @description  Расширение для общения в чатах ITD
// @author       Rationess
// @match        https://xn--d1ah4a.com/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

(function() {
    'use strict';

    const MODULE = "https://raw.githubusercontent.com/EpsilonRationes/ITDCHAT/refs/heads/main/chatModule.js";


    const init = async () => {
        try {
            const url = `${MODULE}?nocache=${Date.now()}`;
            const response = await fetch(url);
            if (!response.ok) return;

            const code = await response.text();
            const script = document.createElement('script');
            script.textContent = code;
            document.head.appendChild(script);
        } catch (e) {}

        window.initChatModule();
    };

    init();
})();
