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

(async function() {
    'use strict';

    function escapeHTML(str) {
        return str.replace(/[&<>"']/g, m => 
            m === '&' ? '&amp;' : m === '<' ? '&lt;' : m === '>' ? '&gt;' : m === '"' ? '&quot;' : '&#39;');
    }

    function formatRelativeTime(isoString) {
        const now = new Date();
        const date = new Date(isoString);
        const diffMs = now - date;
        const seconds = Math.floor(diffMs / 1000);
        if (seconds < 60) return 'только что';
        const minutes = Math.floor(seconds / 60);
        if (minutes < 60) return `${minutes} мин.`;
        const hours = Math.floor(minutes / 60);
        if (hours < 24) return `${hours} ч.`;
        const days = Math.floor(hours / 24);
        return `${days} дн.`;
    }
    // ==================== Вспомогательные функции Base64 ====================
    function arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
        return btoa(binary);
    }

    function base64ToUint8Array(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes;
    }

    // ==================== Глобальный промис готовности ====================
    let resolveChatReady;
    window._itdChatReady = new Promise(resolve => {
        resolveChatReady = resolve;
    });

    // ==================== Класс Ключики ====================
    class Ключики {
        #ready;
        #publicKey;
        #privateKey;

        constructor() {
            this.#ready = this.#init();
        }

        async #init() {
            const pubJwk = localStorage.getItem('rsa_pub_jwk');
            const privJwk = localStorage.getItem('rsa_priv_jwk');
            if (pubJwk && privJwk) {
                try {
                    this.#publicKey = await this.#importPublicJWK(pubJwk);
                    this.#privateKey = await this.#importPrivateJWK(privJwk);
                    return;
                } catch (e) {
                    localStorage.removeItem('rsa_pub_jwk');
                    localStorage.removeItem('rsa_priv_jwk');
                }
            }
            const kp = await crypto.subtle.generateKey(
                { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
                true,
                ['encrypt', 'decrypt']
            );
            this.#publicKey = kp.publicKey;
            this.#privateKey = kp.privateKey;
            localStorage.setItem('rsa_pub_jwk', JSON.stringify(await crypto.subtle.exportKey('jwk', kp.publicKey)));
            localStorage.setItem('rsa_priv_jwk', JSON.stringify(await crypto.subtle.exportKey('jwk', kp.privateKey)));
        }

        async #importPublicJWK(jwkStr) {
            return crypto.subtle.importKey('jwk', JSON.parse(jwkStr), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
        }

        async #importPrivateJWK(jwkStr) {
            return crypto.subtle.importKey('jwk', JSON.parse(jwkStr), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
        }

        async экспортОткрытогоКлюча() {
            await this.#ready;
            const spki = await crypto.subtle.exportKey('spki', this.#publicKey);
            return arrayBufferToBase64(spki);
        }

        async зашифровать(plainText) {
            await this.#ready;
            const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encoded = new TextEncoder().encode(plainText);
            const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, encoded);
            const rawAes = await crypto.subtle.exportKey('raw', aesKey);
            const encryptedAesKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, this.#publicKey, rawAes);
            const encKeyBytes = new Uint8Array(encryptedAesKey);
            const ctBytes = new Uint8Array(ciphertext);
            const totalLen = 2 + encKeyBytes.length + iv.length + ctBytes.length;
            const pack = new Uint8Array(totalLen);
            new DataView(pack.buffer).setUint16(0, encKeyBytes.length, false);
            pack.set(encKeyBytes, 2);
            pack.set(iv, 2 + encKeyBytes.length);
            pack.set(ctBytes, 2 + encKeyBytes.length + iv.length);
            return arrayBufferToBase64(pack.buffer);
        }

        async расшифровать(encryptedBase64) {
            await this.#ready;
            const pack = base64ToUint8Array(encryptedBase64);
            const keyLen = new DataView(pack.buffer).getUint16(0, false);
            const encryptedAesKey = pack.slice(2, 2 + keyLen);
            const iv = pack.slice(2 + keyLen, 2 + keyLen + 12);
            const ciphertext = pack.slice(2 + keyLen + 12);
            const rawAes = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, this.#privateKey, encryptedAesKey);
            const aesKey = await crypto.subtle.importKey('raw', rawAes, { name: 'AES-GCM' }, false, ['decrypt']);
            const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext);
            return new TextDecoder().decode(decrypted);
        }
    }

    // ==================== Класс Апи ====================
    class Апи {
        constructor() {
            this.токен = null;
            this.базовыйURL = 'https://xn--d1ah4a.com';
            this.АЙДИ_ХРАНИТЕЛЯ_ЧАТОВ = '959127ba-f2f7-4e03-adba-f67ee4ff3a93';
            this.идПостаРегистрации = null;
        }

        получитьТокен() { return this.токен; }
        сохранитьТокен(токен) { this.токен = токен; }

        async обновитьТокен() {
            const ответ = await fetch('/api/v1/auth/refresh', { method: 'POST' });
            if (!ответ.ok) throw new Error(`Обновление токена не удалось: ${ответ.status}`);
            const данные = await ответ.json();
            if (!данные.accessToken) throw new Error('В ответе обновления отсутствует accessToken');
            this.сохранитьТокен(данные.accessToken);
            return данные.accessToken;
        }

        async запрос(url, параметры = {}) {
            let токен = this.получитьТокен();
            if (!токен) {
                try { токен = await this.обновитьТокен(); }
                catch (e) { throw new Error('Нет access токена и обновление не удалось'); }
            }
            const заголовки = { 'Content-Type': 'application/json', ...параметры.headers };
            if (токен) заголовки['Authorization'] = `Bearer ${токен}`;
            const параметрыЗапроса = { ...параметры, headers: заголовки };
            let ответ = await fetch(url, параметрыЗапроса);
            if (ответ.status === 401) {
                try {
                    const новыйТокен = await this.обновитьТокен();
                    заголовки['Authorization'] = `Bearer ${новыйТокен}`;
                    параметрыЗапроса.headers = заголовки;
                    ответ = await fetch(url, параметрыЗапроса);
                } catch (e) { throw new Error('Аутентификация не удалась после обновления токена'); }
            }
            return ответ;
        }

        async создатьПост(экстраДанные) {
            const wallRecipientId = this.АЙДИ_ХРАНИТЕЛЯ_ЧАТОВ;
            const базовыйКонтент = 'Я гениальный пользователь расширения (https://github.com/EpsilonRationes/ITDCHAT) и тебе советую. Чаты ещё никому не вредели. ‎';
            const префикс = 'Я гениальный пользователь расширения (';
            const urlGit = 'https://github.com/EpsilonRationes/ITDCHAT';
            const базовыеСпаны = [{ type: 'link', url: urlGit, offset: префикс.length, length: urlGit.length }];
            const части = [];
            for (let i = 0; i < экстраДанные.length; i += 1000) части.push(экстраДанные.substring(i, i + 1000));
            const дополнительныеСпаны = [];
            if (части.length > 0) {
                const offset = базовыйКонтент.length - 1;
                for (const часть of части) дополнительныеСпаны.push({ type: 'link', url: часть, offset, length: 1 });
            }
            const всеСпаны = [...базовыеСпаны, ...дополнительныеСпаны];
            const тело = { content: базовыйКонтент, spans: всеСпаны, wallRecipientId };
            const url = `${this.базовыйURL}/api/posts`;
            return await this.запрос(url, { method: 'POST', body: JSON.stringify(тело) });
        }

        async зарегистрироватьПользователя(ключики) {
            const LS_KEY = 'reg_post_id';
            const сохранённыйId = localStorage.getItem(LS_KEY);
            if (сохранённыйId) {
                this.идПостаРегистрации = сохранённыйId;
                return сохранённыйId;
            }
            const открытыйКлюч = await ключики.экспортОткрытогоКлюча();
            const данныеДляПоста = JSON.stringify({ мойОткрытыйКлючик: открытыйКлюч });
            const ответ = await this.создатьПост(данныеДляПоста);
            if (!ответ.ok) throw new Error(`Ошибка создания регистрационного поста: ${ответ.status}`);
            const пост = await ответ.json();
            const postId = пост.id;
            if (!postId) throw new Error('В ответе отсутствует id поста');
            localStorage.setItem(LS_KEY, postId);
            this.идПостаРегистрации = postId;
            return postId;
        }

        async найтиПользователей() {
            const всеПользователи = new Map();
            let cursor = null, hasMore = true;
            while (hasMore) {
                let url = `${this.базовыйURL}/api/posts/user/itd_chat?limit=20&sort=new`;
                if (cursor) url += `&cursor=${encodeURIComponent(cursor)}`;
                const ответ = await this.запрос(url, { method: 'GET' });
                if (!ответ.ok) throw new Error(`Ошибка получения постов: ${ответ.status}`);
                const данные = await ответ.json();
                const посты = данные.data?.posts || [];
                const пагинация = данные.data?.pagination || {};
                cursor = пагинация.nextCursor || null;
                hasMore = пагинация.hasMore || false;
                for (const пост of посты) {
                    if (всеПользователи.has(пост.author.id)) continue;
                    const спаны = пост.spans || [];
                    if (спаны.length < 2) continue;
                    let склеенныеДанные = '';
                    for (let i = 1; i < спаны.length; i++) склеенныеДанные += спаны[i].url || '';
                    if (!склеенныеДанные) continue;
                    let данныеПоста;
                    try { данныеПоста = JSON.parse(склеенныеДанные); } catch (e) { continue; }
                    if (данныеПоста?.мойОткрытыйКлючик && typeof данныеПоста.мойОткрытыйКлючик === 'string' && данныеПоста.мойОткрытыйКлючик.length > 0) {
                        всеПользователи.set(пост.author.id, {
                            отображаемоеИмя: пост.author.displayName,
                            имяПользователя: пост.author.username,
                            айди: пост.author.id,
                            открытыйКлюч: данныеПоста.мойОткрытыйКлючик,
                            айдиПостаРегистрации: пост.id,
                            аватарка: пост.author.avatar || ''
                        });
                    }
                }
            }
            return Array.from(всеПользователи.values());
        }

        async проверитьОбновления(массивПользователей) {
            const url = `${this.базовыйURL}/api/posts/user/itd_chat?limit=20&sort=new`;
            const ответ = await this.запрос(url, { method: 'GET' });
            if (!ответ.ok) throw new Error(`Ошибка получения обновлений: ${ответ.status}`);
            const данные = await ответ.json();
            const посты = данные.data?.posts || [];
            const существующиеАйди = new Set(массивПользователей.map(u => u.айди));
            for (const пост of посты) {
                if (существующиеАйди.has(пост.author.id)) continue;
                const спаны = пост.spans || [];
                if (спаны.length < 2) continue;
                let склеенныеДанные = '';
                for (let i = 1; i < спаны.length; i++) склеенныеДанные += спаны[i].url || '';
                if (!склеенныеДанные) continue;
                let данныеПоста;
                try { данныеПоста = JSON.parse(склеенныеДанные); } catch (e) { continue; }
                if (данныеПоста?.мойОткрытыйКлючик && typeof данныеПоста.мойОткрытыйКлючик === 'string' && данныеПоста.мойОткрытыйКлючик.length > 0) {
                    массивПользователей.push({
                        отображаемоеИмя: пост.author.displayName,
                        имяПользователя: пост.author.username,
                        айди: пост.author.id,
                        открытыйКлюч: данныеПоста.мойОткрытыйКлючик,
                        айдиПостаРегистрации: пост.id,
                        аватарка: пост.author.avatar || ''
                    });
                    существующиеАйди.add(пост.author.id);
                }
            }
        }

        async получитьВходящиеСообщения(ключики) {
            const postId = this.идПостаРегистрации;
            if (!postId) { console.warn('Нет ID регистрационного поста'); return []; }
            const STORAGE_KEY = `read_comments_${postId}`;
            let readIds;
            try { readIds = new Set(JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]')); } catch { readIds = new Set(); }
            const сообщения = [];
            let cursor = null, hasMore = true, stopPagination = false;
            while (hasMore && !stopPagination) {
                let url = `${this.базовыйURL}/api/posts/${postId}/comments?limit=100&sort=newest`;
                if (cursor) url += `&cursor=${encodeURIComponent(cursor)}`;
                const ответ = await this.запрос(url, { method: 'GET' });
                if (!ответ.ok) throw new Error(`Ошибка получения комментариев: ${ответ.status}`);
                const данные = await ответ.json();
                const комментарии = данные.data?.comments || [];

                // ===== ВСТАВЛЯЕМ СОРТИРОВКУ ПО ДАТЕ (от новых к старым) =====
                комментарии.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
                // ============================================================

                hasMore = данные.data?.hasMore ?? false;
                cursor = данные.data?.nextCursor || null;
                for (const коммент of комментарии) {
                    if (readIds.has(коммент.id)) { stopPagination = true; break; }
                    let расшифрованное;
                    try { расшифрованное = await ключики.расшифровать(коммент.content); }
                    catch { readIds.add(коммент.id); continue; }
                    сообщения.push({
                        сообщение: расшифрованное,
                        аватарка: коммент.author.avatar,
                        айди: коммент.author.id,
                        имяПользователя: коммент.author.username,
                        отображаемоеИмя: коммент.author.displayName,
                        времяСоздания: коммент.createdAt
                    });
                    readIds.add(коммент.id);
                }
            }
            localStorage.setItem(STORAGE_KEY, JSON.stringify([...readIds]));
            return сообщения;
        }
        async подписаться(идПользователя = this.АЙДИ_ХРАНИТЕЛЯ_ЧАТОВ) {
            const url = `${this.базовыйURL}/api/users/${идПользователя}/follow`;
            const ответ = await this.запрос(url, { method: 'POST' });
            if (!ответ.ok) throw new Error(`Ошибка подписки: ${ответ.status}`);
            return ответ.json();
        }
    }

    // ==================== Функции шифрования для отправки ====================
    async function импортироватьОткрытыйКлюч(base64Key) {
        const binaryDer = Uint8Array.from(atob(base64Key), c => c.charCodeAt(0));
        return crypto.subtle.importKey('spki', binaryDer, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
    }

    async function зашифроватьДляПользователя(открытыйКлюч, сообщение) {
        const publicKey = await импортироватьОткрытыйКлюч(открытыйКлюч);
        const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(сообщение);
        const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, encoded);
        const rawAes = await crypto.subtle.exportKey('raw', aesKey);
        const encryptedAesKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, rawAes);
        const encKeyBytes = new Uint8Array(encryptedAesKey);
        const ctBytes = new Uint8Array(ciphertext);
        const totalLen = 2 + encKeyBytes.length + iv.length + ctBytes.length;
        const pack = new Uint8Array(totalLen);
        new DataView(pack.buffer).setUint16(0, encKeyBytes.length, false);
        pack.set(encKeyBytes, 2);
        pack.set(iv, 2 + encKeyBytes.length);
        pack.set(ctBytes, 2 + encKeyBytes.length + iv.length);
        const binary = String.fromCharCode(...pack);
        return btoa(binary);
    }

    // ==================== Декодирование JWT ====================
    function parseJwt(token) {
        try {
            const base64Url = token.split('.')[1];
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            const jsonPayload = decodeURIComponent(atob(base64).split('').map(c =>
                '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
            ).join(''));
            return JSON.parse(jsonPayload);
        } catch (e) {
            console.error('Ошибка парсинга JWT', e);
            return null;
        }
    }

    // ==================== Получение информации о текущем пользователе ====================
    function getCurrentUserInfo() {
        const апи = window.апи;
        if (!апи || !апи.получитьТокен) {
            return { id: 'unknown', username: 'Я', displayName: 'Я', avatar: '', verified: false, pin: null, hasNuksta: false };
        }
        const token = апи.получитьТокен();
        if (!token) {
            return { id: 'unknown', username: 'Я', displayName: 'Я', avatar: '', verified: false, pin: null, hasNuksta: false };
        }
        const payload = parseJwt(token);
        if (!payload || !payload.sub) {
            return { id: 'unknown', username: 'Я', displayName: 'Я', avatar: '', verified: false, pin: null, hasNuksta: false };
        }
        const myId = payload.sub;
        let myUsername = 'Я';
        let myDisplayName = 'Я';
        let myAvatar = '';
        if (window.НеЗнаюКакНазвать && window.НеЗнаюКакНазвать.пользователи) {
            const я = window.НеЗнаюКакНазвать.пользователи.find(u => u.айди === myId);
            if (я) {
                myUsername = я.имяПользователя || myUsername;
                myDisplayName = я.отображаемоеИмя || myDisplayName;
                myAvatar = я.аватарка || '';
            }
        }
        return {
            id: myId,
            username: myUsername,
            displayName: myDisplayName,
            avatar: myAvatar,
            verified: false,
            pin: null,
            hasNuksta: false
        };
    }

    // ==================== Класс ChatManager ====================
    class НеЗнаюКакНазвать {
        constructor(апи, ключики) {
            this.апи = апи;
            this.ключики = ключики;
            this.пользователи = [];
            this.чаты = {};
            this.интервалОбновления = null;
        }

        async инициализировать() {
            const сохранённые = localStorage.getItem('itd_chat_store');
            if (сохранённые) {
                try {
                    this.чаты = JSON.parse(сохранённые);
                } catch (e) {
                    console.warn('Ошибка парсинга чатов из localStorage, начинаем с чистого');
                    this.чаты = {};
                }
            }

            await this.обновитьПользователей();

            this.интервалОбновления = setInterval(() => this.обновитьПользователей(), 60_000);
        }

        async обновитьПользователей() {
            try {
                if (this.пользователи.length === 0) {
                    this.пользователи = await this.апи.найтиПользователей();
                } else {
                    await this.апи.проверитьОбновления(this.пользователи);
                }
                this._синхронизироватьДанныеПользователей();
            } catch (e) {
                console.error('Ошибка обновления пользователей:', e);
            }
        }

        _синхронизироватьДанныеПользователей() {
            for (const п of this.пользователи) {
                if (!this.чаты[п.айди]) {
                    this.чаты[п.айди] = {
                        аватарка: п.аватарка || '',
                        отображаемоеИмя: п.отображаемоеИмя,
                        имяПользователя: п.имяПользователя,
                        айди: п.айди,
                        сообщения: []
                    };
                } else {
                    if (п.аватарка) this.чаты[п.айди].аватарка = п.аватарка;
                    this.чаты[п.айди].отображаемоеИмя = п.отображаемоеИмя;
                    this.чаты[п.айди].имяПользователя = п.имяПользователя;
                }
            }
            this._сохранитьЧаты();
        }

        _сохранитьЧаты() {
            localStorage.setItem('itd_chat_store', JSON.stringify(this.чаты));
        }

        async отправитьСообщение(пользователь, текст) {
            if (!пользователь.открытыйКлюч) throw new Error('Нет открытого ключа пользователя');
            const зашифрованныйПакет = await зашифроватьДляПользователя(пользователь.открытыйКлюч, текст);
            if (зашифрованныйПакет.length > 1000) {
                throw new Error('Сообщение слишком длинное, зашифрованный пакет превышает 1000 символов.');
            }
            const url = `${this.апи.базовыйURL}/api/posts/${пользователь.айдиПостаРегистрации}/comments`;
            const тело = { content: зашифрованныйПакет };
            const ответ = await this.апи.запрос(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(тело)
            });
            if (!ответ.ok) {
                const ошибка = await ответ.text();
                throw new Error(`Ошибка отправки: ${ответ.status} ${ошибка}`);
            }
            const чат = this._получитьИлиСоздатьЧат(пользователь.айди, пользователь);
            чат.сообщения.push({
                моёСообщение: true,
                сообщение: текст,
                времяОтправки: new Date().toISOString()
            });
            this._сохранитьЧаты();
            return ответ.json();
        }

        _получитьИлиСоздатьЧат(айди, данныеПользователя = null) {
            if (!this.чаты[айди]) {
                this.чаты[айди] = {
                    аватарка: данныеПользователя?.аватарка || '',
                    отображаемоеИмя: данныеПользователя?.отображаемоеИмя || '',
                    имяПользователя: данныеПользователя?.имяПользователя || '',
                    айди: айди,
                    сообщения: []
                };
            }
            return this.чаты[айди];
        }

        async получитьСообщения() {
            try {
                const входящие = await this.апи.получитьВходящиеСообщения(this.ключики);
                for (const msg of входящие) {
                    const чат = this._получитьИлиСоздатьЧат(msg.айди, {
                        аватарка: msg.аватарка,
                        отображаемоеИмя: msg.отображаемоеИмя,
                        имяПользователя: msg.имяПользователя
                    });
                    чат.сообщения.push({
                        моёСообщение: false,
                        сообщение: msg.сообщение,
                        времяСоздания: msg.времяСоздания
                    });
                    if (msg.аватарка) чат.аватарка = msg.аватарка;
                }
                if (входящие.length > 0) {
                    this._сохранитьЧаты();
                }
                return входящие;
            } catch (e) {
                console.error('Ошибка получения входящих сообщений:', e);
                return [];
            }
        }

        найтиПользователяПоАйди(айди) {
            return this.пользователи.find(u => u.айди === айди) || null;
        }

        остановить() {
            if (this.интервалОбновления) {
                clearInterval(this.интервалОбновления);
                this.интервалОбновления = null;
            }
        }
    }

    // ==================== Перехват fetch (пост + комментарии + уведомления) ====================
    const originalFetch = window.fetch;

    window.fetch = async function(url, options) {
        let urlString = url instanceof Request ? url.url : url.toString();
        console.log(urlString);

        // Перехват GET /api/posts/@<userId> – подмена поста
        const postMatch = urlString.match(/^\/api\/posts\/@([^/?]+)$/);
        if (postMatch && (!options || (options.method || 'GET').toUpperCase() === 'GET')) {
            await window._itdChatReady;
            const userId = postMatch[1];
            if (window.НеЗнаюКакНазвать && typeof window.НеЗнаюКакНазвать.найтиПользователяПоАйди === 'function') {
                const пользователь = window.НеЗнаюКакНазвать.найтиПользователяПоАйди(userId);
                if (пользователь) {
                    const fakeData = {
                        data: {
                            id: пользователь.айдиПостаРегистрации,
                            content: "",
                            spans: [],
                            author: {
                                id: пользователь.айди,
                                username: пользователь.имяПользователя || "",
                                displayName: пользователь.отображаемоеИмя || "",
                                avatar: пользователь.аватарка || "",
                                verified: false,
                                pin: null,
                                hasNuksta: false
                            },
                            attachments: [],
                            likesCount: 0,
                            commentsCount: 0,
                            repostsCount: 0,
                            viewsCount: 0,
                            isLiked: false,
                            isReposted: false,
                            isViewed: true,
                            isOwner: false,
                            createdAt: new Date().toISOString(),
                            comments: [],
                            originalPost: null,
                            wallRecipientId: null,
                            wallRecipient: null,
                            poll: null,
                            dominantEmoji: null,
                            editedAt: null,
                            vs: ""
                        }
                    };
                    const response = new Response(JSON.stringify(fakeData), {
                        status: 200,
                        statusText: 'OK',
                        headers: { 'Content-Type': 'application/json' }
                    });
                    return response;
                }
            }
            return originalFetch.apply(this, arguments);
        }

        // Перехват GET /api/posts/@<userId>/comments – подмена комментариев чатом
        const commentsMatch = urlString.match(/^\/api\/posts\/@([^/?]+)\/comments/);
        if (commentsMatch && (!options || (options.method || 'GET').toUpperCase() === 'GET')) {
            await window._itdChatReady;
            try {
                await window.НеЗнаюКакНазвать.получитьСообщения();
            } catch (e) {
                console.error('Ошибка при загрузке свежих сообщений:', e);
                // продолжаем с теми данными, что есть
            }
            const userId = commentsMatch[1];
            if (window.НеЗнаюКакНазвать && window.НеЗнаюКакНазвать.чаты) {
                const chat = window.НеЗнаюКакНазвать.чаты[userId];
                if (chat && chat.сообщения && chat.сообщения.length > 0) {
                    try {
                        const myInfo = getCurrentUserInfo();

                        const urlObj = new URL(urlString, window.location.origin);
                        const limit = parseInt(urlObj.searchParams.get('limit')) || 100;
                        const cursor = urlObj.searchParams.get('cursor');
                        let startIndex = 0;
                        if (cursor) {
                            const parsed = parseInt(cursor);
                            if (!isNaN(parsed) && parsed >= 0) startIndex = parsed;
                        }

                        const sortedMessages = chat.сообщения.map((msg, originalIndex) => ({
                            ...msg,
                            time: msg.времяСоздания || msg.времяОтправки || new Date().toISOString(),
                            _idx: originalIndex
                        })).sort((a, b) => new Date(b.time) - new Date(a.time));

                        const total = sortedMessages.length;
                        const pageMessages = sortedMessages.slice(startIndex, startIndex + limit);
                        const hasMore = (startIndex + limit) < total;
                        const nextCursor = hasMore ? String(startIndex + limit) : null;

                        const comments = pageMessages.map((msg) => {
                            const isMine = msg.моёСообщение;
                            const author = isMine ? myInfo : {
                                id: userId,
                                username: chat.имяПользователя || '',
                                displayName: chat.отображаемоеИмя || '',
                                avatar: chat.аватарка || '',
                                verified: false,
                                pin: null,
                                hasNuksta: false
                            };
                            return {
                                id: `chat-msg-${userId}-${msg._idx}`,
                                content: msg.сообщение,
                                author: author,
                                likesCount: 0,
                                repliesCount: 0,
                                isLiked: false,
                                createdAt: msg.time,
                                attachments: [],
                                replies: []
                            };
                        });

                        const fakeResponse = {
                            data: {
                                comments: comments,
                                total: total,
                                hasMore: hasMore,
                                nextCursor: nextCursor
                            }
                        };

                        const response = new Response(JSON.stringify(fakeResponse), {
                            status: 200,
                            statusText: 'OK',
                            headers: { 'Content-Type': 'application/json' }
                        });
                        return response;
                    } catch (e) {
                        console.error('Ошибка при формировании фиктивных комментариев:', e);
                    }
                }
            }
            return originalFetch.apply(this, arguments);
        }

        // Перехват POST /api/posts/@<userId>/comments – отправка через чат
        const postCommentMatch = urlString.match(/^\/api\/posts\/@([^/?]+)\/comments$/);
        if (postCommentMatch && options && (options.method || 'GET').toUpperCase() === 'POST') {
            await window._itdChatReady;
            const userId = postCommentMatch[1];
            if (window.НеЗнаюКакНазвать && typeof window.НеЗнаюКакНазвать.отправитьСообщение === 'function') {
                const пользователь = window.НеЗнаюКакНазвать.найтиПользователяПоАйди(userId);
                if (пользователь) {
                    let content;
                    try {
                        if (typeof options.body === 'string') {
                            const bodyObj = JSON.parse(options.body);
                            content = bodyObj.content;
                        } else if (options.body instanceof URLSearchParams) {
                            content = options.body.get('content');
                        } else if (options.body instanceof FormData) {
                            content = options.body.get('content');
                        }
                    } catch (e) {
                        console.error('Не удалось разобрать тело POST запроса:', e);
                        return originalFetch.apply(this, arguments);
                    }

                    if (!content) {
                        return originalFetch.apply(this, arguments);
                    }

                    try {
                        await window.НеЗнаюКакНазвать.отправитьСообщение(пользователь, content);

                        const myInfo = getCurrentUserInfo();
                        const fakeComment = {
                            id: crypto.randomUUID ? crypto.randomUUID() : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
                                const r = Math.random() * 16 | 0;
                                const v = c === 'x' ? r : (r & 0x3 | 0x8);
                                return v.toString(16);
                            }),
                            content: content,
                            author: myInfo,
                            likesCount: 0,
                            repliesCount: 0,
                            isLiked: false,
                            createdAt: new Date().toISOString(),
                            attachments: []
                        };

                        return new Response(JSON.stringify(fakeComment), {
                            status: 200,
                            statusText: 'OK',
                            headers: { 'Content-Type': 'application/json' }
                        });
                    } catch (e) {
                        console.error('Ошибка при отправке сообщения через чат:', e);
                        return new Response(JSON.stringify({ error: e.message }), {
                            status: 500,
                            headers: { 'Content-Type': 'application/json' }
                        });
                    }
                }
            }
            return originalFetch.apply(this, arguments);
        }

        // Перехват GET /api/notifications – замена preview для чатов
        if (urlString.startsWith('/api/notifications') && (!options || (options.method || 'GET').toUpperCase() === 'GET')) {
            await window._itdChatReady;
            const postId = window.апи?.идПостаРегистрации;
            if (postId) {
                try {
                    const originalResponse = await originalFetch.apply(this, arguments);
                    const data = await originalResponse.json();
                    if (data.notifications && Array.isArray(data.notifications)) {
                        data.notifications.forEach(notif => {
                            if (notif.targetType === 'post' && notif.targetId === postId) {
                                notif.preview = '[вам написали]';
                            }
                        });
                    }
                    const modifiedBody = JSON.stringify(data);
                    return new Response(modifiedBody, {
                        status: originalResponse.status,
                        statusText: originalResponse.statusText,
                        headers: originalResponse.headers
                    });
                } catch (e) {
                    console.error('Ошибка модификации уведомлений:', e);
                }
            }
            return originalFetch.apply(this, arguments);
        }

        if (urlString.startsWith('/api/notifications') && (!options || (options.method || 'GET').toUpperCase() === 'GET')) {
            await window._itdChatReady;
            const regPostId = window.апи?.идПостаРегистрации;
            if (regPostId) {
                try {
                    const originalResponse = await originalFetch.apply(this, arguments);
                    const clonedResponse = originalResponse.clone();
                    const data = await clonedResponse.json();
                    if (data && Array.isArray(data.notifications)) {
                        let modified = false;
                        for (const notif of data.notifications) {
                            if (notif.targetType === 'post' && notif.targetId === regPostId) {
                                if (notif.preview !== '[вам написали]') {
                                    notif.preview = '[вам написали]';
                                    modified = true;
                                }
                            }
                        }
                        if (modified) {
                            const modifiedBody = JSON.stringify(data);
                            return new Response(modifiedBody, {
                                status: originalResponse.status,
                                statusText: originalResponse.statusText,
                                headers: originalResponse.headers
                            });
                        }
                    }
                    return originalResponse;
                } catch (e) {
                    console.error('Ошибка модификации уведомлений:', e);
                    return originalFetch.apply(this, arguments);
                }
            }
            return originalFetch.apply(this, arguments);
        }

        // Все остальные запросы идут как обычно
        return originalFetch.apply(this, arguments);
    };

    // ==================== Главная инициализация ====================
    const апи = new Апи();
    const ключики = new Ключики();

    window.апи = апи;

    const SUBSCRIBED_FLAG = 'itd_subscribed';
    if (!localStorage.getItem(SUBSCRIBED_FLAG)) {
        try {
            await апи.подписаться();
            localStorage.setItem(SUBSCRIBED_FLAG, 'true');
        } catch (e) {
            if (e.message?.includes('409')) {
                // Подписка уже существует — считаем выполненной
                localStorage.setItem(SUBSCRIBED_FLAG, 'true');
            } else {
                console.warn('Неожиданная ошибка подписки:', e);
            }
        }
    }

    const postId = await апи.зарегистрироватьПользователя(ключики);
    console.log('Регистрационный пост:', postId);

    const chatManager = new НеЗнаюКакНазвать(апи, ключики);
    await chatManager.инициализировать();

    window.НеЗнаюКакНазвать = chatManager;
    resolveChatReady();
    console.log('Расширение ITD Chat готово. Используйте window.НеЗнаюКакНазвать для работы с чатами.');

    const regPostId = апи.идПостаРегистрации;
    if (regPostId) {
        let sseAbortController = new AbortController();

        async function startSSE() {
            try {
                let token = апи.получитьТокен();
                if (!token) {
                    await апи.обновитьТокен();
                    token = апи.получитьТокен();
                }
                const response = await fetch('https://xn--d1ah4a.com/api/notifications/stream', {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    },
                    signal: sseAbortController.signal
                });

                if (!response.ok) {
                    if (response.status === 401) {
                        await апи.обновитьТокен();
                        startSSE();
                        return;
                    }
                    throw new Error(`SSE ошибка: ${response.status}`);
                }

                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                let buffer = '';
                let eventType = '';

                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;

                    buffer += decoder.decode(value, { stream: true });
                    const lines = buffer.split('\n');
                    buffer = lines.pop(); // неполная строка

                    for (const line of lines) {
                        if (line.startsWith('event: ')) {
                            eventType = line.slice(7).trim();
                        } else if (line.startsWith('data: ')) {
                            const dataStr = line.slice(6);
                            if (eventType === 'notification') {
                                try {
                                    const data = JSON.parse(dataStr);
                                    if (data.targetType === 'post' && data.targetId === regPostId) {
                                        const actorId = data.actor.id;
                                        const currentPath = window.location.pathname;
                                        const chatMatch = currentPath.match(/^\/@itd_chat\/post\/@([a-f0-9\-]+)$/);

                                        if (chatMatch && chatMatch[1] === actorId) {
                                            const chat = chatManager.чаты[actorId];
                                            if (!chat) continue;
                                            const prevLength = chat.сообщения.length;

                                            await chatManager.получитьСообщения();
                                            const newMessages = chat.сообщения.slice(prevLength);
                                            if (newMessages.length === 0) continue;

                                            const commentContainer = document.querySelector('.bPsq')?.parentElement;
                                            if (!commentContainer) continue;

                                            newMessages.forEach((msg, i) => {
                                                const isMy = msg.моёСообщение;
                                                const author = isMy ? getCurrentUserInfo() : {
                                                    displayName: chat.отображаемоеИмя || '',
                                                    username: chat.имяПользователя || '',
                                                    avatar: chat.аватарка || ''
                                                };
                                                const timeStr = formatRelativeTime(msg.времяСоздания || msg.времяОтправки || new Date().toISOString());
                                                const commentEl = document.createElement('div');
                                                commentEl.className = 'bPsq';
                                                commentEl.innerHTML = `
                                                    <div data-comment-id="chat-msg-${actorId}-${prevLength + i}" class="maGB ">
                                                        <div data-comment-id="chat-msg-${actorId}-${prevLength + i}" class="yNOK ">
                                                            <div class="ym9o">
                                                                <a href="/@${author.username}" class="JZXd">
                                                                    <div class="upUc baUP ">
                                                                        <span class="coZf">${author.avatar || ''}</span>
                                                                    </div>
                                                                </a>
                                                            </div>
                                                            <div class="UQY2">
                                                                <div class="IAuq ">
                                                                    <div class="bLlH">
                                                                        <div class="jHVZ">
                                                                            <div class="ar9o">
                                                                                <a href="/@${author.username}" class="mlj1">
                                                                                    <span class="a79x MCTW ">
                                                                                        <span class="Rslh">${escapeHTML(author.displayName)}</span>
                                                                                    </span>
                                                                                </a>
                                                                                <span class="xpHx">${timeStr}</span>
                                                                            </div>
                                                                            <div class="DX4i TqxH"></div>
                                                                        </div>
                                                                        <div class="vGe0">
                                                                            <span><span>${escapeHTML(msg.сообщение)}</span></span>
                                                                        </div>
                                                                    </div>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    </div>`;
                                                commentContainer.prepend(commentEl);
                                            });
                                        }
                                    }
                                } catch (e) {}
                            }
                            eventType = ''; // сброс после data
                        } else if (line.trim() === '') {
                            eventType = ''; // пустая строка завершает событие
                        }
                    }
                }
            } catch (err) {
                if (err.name === 'AbortError') return;
                console.error('SSE ошибка, переподключение через 5с:', err);
                setTimeout(startSSE, 5000);
            }
        }

        startSSE();
        window._sseStop = () => sseAbortController.abort();
    }

    function injectWriteButtonOnProfile() {
        // Ищем кнопку подписки/отписки
        const buttons = document.querySelectorAll('button');
        let targetButton = null;
        for (const btn of buttons) {
            const txt = btn.textContent.trim();
            if (txt === 'Подписаться' || txt === 'Подписатьcz' || txt === 'Вы подписаны') {
                targetButton = btn;
                break;
            }
        }
        if (!targetButton) return;

        const parent = targetButton.parentElement;
        if (!parent) return;

        // Не добавляем повторно
        if (parent.querySelector('[data-chat-write-btn]')) return;

        // Извлекаем username из URL: /@username
        const pathMatch = window.location.pathname.match(/^\/@(.+)$/);
        if (!pathMatch) return;
        const profileUsername = pathMatch[1];

        // Проверяем, что этот пользователь зарегистрирован в чате и находим его UUID
        if (!window.НеЗнаюКакНазвать || !window.НеЗнаюКакНазвать.пользователи) return;
        const user = window.НеЗнаюКакНазвать.пользователи.find(
            u => u.имяПользователя === profileUsername
        );
        if (!user || !user.айди) return; // если пользователь не найден или нет UUID

        // Создаём кнопку
        const writeBtn = document.createElement('button');
        writeBtn.textContent = 'Написать';
        writeBtn.className = targetButton.className; // копируем все CSS-классы
        writeBtn.setAttribute('data-chat-write-btn', 'true');
        writeBtn.addEventListener('click', () => {
            // Переход на страницу чата с этим пользователем
            window.location.href = `https://xn--d1ah4a.com/@itd_chat/post/@${user.айди}`;
        });

        // Вставляем кнопку после кнопки подписки
        parent.insertBefore(writeBtn, targetButton.nextSibling);
    }

    // Запускаем сразу и подписываемся на изменения DOM (SPA)
    injectWriteButtonOnProfile();
    const profileObserver = new MutationObserver(() => injectWriteButtonOnProfile());
    profileObserver.observe(document.body, { childList: true, subtree: true });

    // ==================== Модификация страницы чата ====================
    let lastModifiedChatURL = null;

    function modifyChatPage() {
        // Только для URL вида /@.../post/@UUID
        const match = window.location.pathname.match(/^\/@[^\/]+\/post\/@([a-f0-9\-]+)$/);
        if (!match) return;

        const userId = match[1];
        const chatName =
            (window.НеЗнаюКакНазвать?.чаты?.[userId]?.отображаемоеИмя) ||
            (window.НеЗнаюКакНазвать?.чаты?.[userId]?.имяПользователя) ||
            'Пользователь';

        // Проверяем, есть ли элементы, которые нужно удалить/изменить.
        // Если ничего нет – выходим, чтобы не дёргать DOM зря.
        const selectToRemove = document.querySelector('select');
        const hasSortSelect = selectToRemove && ['new','old','popular'].every(v =>
            Array.from(selectToRemove.options).some(o => o.value === v)
        );
        const timeElements = document.querySelectorAll('time');
        const replyButtons = Array.from(document.querySelectorAll('button')).filter(btn =>
            btn.textContent.trim() === 'Ответить'
        );
        const footerElements = document.querySelectorAll('footer');
        const h1Elements = Array.from(document.querySelectorAll('h1')).filter(h1 =>
            h1.textContent.includes('Пост') || h1.textContent.startsWith('Чат с')
        );

        // Если все элементы уже убраны/заменены – выходим
        if (!hasSortSelect && timeElements.length === 0 && replyButtons.length === 0 && footerElements.length === 0) {
            // Проверим, вдруг h1 ещё содержит «Пост» и надо заменить
            const needH1Fix = h1Elements.some(h1 => h1.textContent.includes('Пост') && !h1.textContent.startsWith('Чат с'));
            if (!needH1Fix) return;
        }

        // Удаляем select сортировки (если есть)
        if (hasSortSelect) {
            selectToRemove.remove();
        }

        // Удаляем все метки времени
        timeElements.forEach(time => time.remove());

        // Удаляем блоки с кнопкой «Ответить»
        replyButtons.forEach(btn => {
            const parent = btn.parentElement;
            if (parent) parent.remove();
        });

        // Удаляем все footer
        footerElements.forEach(f => f.remove());

        // Удаляем кнопку с троеточием (родитель указанного SVG)
        document.querySelectorAll('svg').forEach(svg => {
            if (svg.outerHTML === '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="none" viewBox="0 0 18 18"><path fill="currentColor" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 9.75a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5ZM14.25 9.75a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5ZM3.75 9.75a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5Z"></path></svg>') {
                const parent = svg.parentElement;
                if (parent) parent.remove();
            }
        });

        // Удаляем родительский элемент для SVG (кнопка "прикрепить")
        document.querySelectorAll('svg').forEach(svg => {
            if (svg.outerHTML === '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="none" viewBox="0 0 20 20"><path stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="1.833" d="m17.867 9.208-7.659 7.659a5.003 5.003 0 1 1-7.075-7.075l7.659-7.659a3.335 3.335 0 1 1 4.716 4.717l-7.666 7.658a1.667 1.667 0 1 1-2.359-2.358l7.075-7.067"></path></svg>') {
                const parent = svg.parentElement;
                if (parent) parent.remove();
            }
        });

        // Удаляем родительский элемент для SVG (кнопка голосового сообщения)
        document.querySelectorAll('svg').forEach(svg => {
            if (svg.outerHTML === '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="none" viewBox="0 0 18 18"><g stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2"><path d="M9 2c-.53 0-1.04.219-1.414.608C7.21 2.998 7 3.526 7 4.077v4.846c0 .55.21 1.08.586 1.469.375.39.884.608 1.414.608.53 0 1.04-.219 1.414-.608.375-.39.586-.918.586-1.469V4.077c0-.55-.21-1.08-.586-1.469A1.963 1.963 0 0 0 9 2Z"></path><path d="M14 8v1.333c0 1.238-.527 2.425-1.464 3.3C11.598 13.508 10.326 14 9 14s-2.598-.492-3.536-1.367C4.527 11.758 4 10.571 4 9.333V8M9 14v2"></path></g></svg>') {
                const parent = svg.parentElement;
                if (parent) parent.remove();
            }
        });

        document.querySelectorAll('[data-placeholder="Написать комментарий..."]').forEach(el => {
            el.setAttribute('data-placeholder', 'Написать...');
        });

        // Заменяем заголовок h1
        h1Elements.forEach(h1 => {
            if (h1.textContent.includes('Пост') && !h1.textContent.startsWith('Чат с')) {
                h1.textContent = `Чат с ${chatName}`;
            }
        });
    }

    // Запускаем сразу и наблюдаем за изменениями DOM
    if (document.body) modifyChatPage();
    const chatObserver = new MutationObserver(() => modifyChatPage());
    chatObserver.observe(document.body, { childList: true, subtree: true });

    // ==================== Модификация страницы уведомлений ====================
    function modifyNotificationsPage() {
        // Ждём готовности менеджера
        if (!window.НеЗнаюКакНазвать || !window.апи) return;

        document.querySelectorAll('div[role="button"].KUNv:not([data-chat-notification-modified])').forEach(el => {
            const previewEl = el.querySelector('p.GmfV');
            if (previewEl && previewEl.textContent === '[вам написали]') {
                // Меняем текст действия
                const bstzEl = el.querySelector('span.BSTZ');
                if (bstzEl) {
                    bstzEl.textContent = 'написал(а) вам';
                }

                // Извлекаем username из ссылки на профиль
                const profileLink = el.querySelector('a.yZCl');
                if (profileLink) {
                    const href = profileLink.getAttribute('href');
                    const usernameMatch = href && href.match(/^\/@(.+)$/);
                    if (usernameMatch) {
                        const username = usernameMatch[1];

                        // Переопределяем клик
                        el.addEventListener('click', (event) => {
                            event.preventDefault();
                            event.stopImmediatePropagation();
                            event.stopPropagation();

                            const user = window.НеЗнаюКакНазвать.пользователи.find(u => u.имяПользователя === username);
                            if (user) {
                                window.location.href = `https://xn--d1ah4a.com/@itd_chat/post/@${user.айди}`;
                            } else {
                                // fallback
                                window.location.href = `https://xn--d1ah4a.com/@${username}`;
                            }
                        }, true); // фаза захвата, чтобы перехватить до других обработчиков
                    }
                }
                el.setAttribute('data-chat-notification-modified', 'true');
            }
        });
    }

    // Активируем только на странице уведомлений
    if (window.location.pathname.startsWith('/notifications')) {
        if (document.body) modifyNotificationsPage();
        const notifObserver = new MutationObserver(() => modifyNotificationsPage());
        notifObserver.observe(document.body, { childList: true, subtree: true });
    }

    // Модификация страницы уведомлений
    function processNotificationElements() {
        // Ищем все элементы p с текстом "[вам написали]" (так мы модифицировали preview)
        const allParagraphs = document.querySelectorAll('p');
        for (const p of allParagraphs) {
            if (p.textContent.trim() === '[вам написали]') {
                // Находим родительский контейнер уведомления (элемент с role="button")
                const notificationContainer = p.closest('[role="button"]');
                if (!notificationContainer || notificationContainer.dataset.chatProcessed === 'true') continue;
                notificationContainer.dataset.chatProcessed = 'true';

                // Меняем текст "прокомментировал(а) ваш пост" на "написал(а) вам"
                const spans = notificationContainer.querySelectorAll('span');
                for (const span of spans) {
                    if (span.textContent.includes('прокомментировал(а) ваш пост')) {
                        span.textContent = span.textContent.replace('прокомментировал(а) ваш пост', 'написал(а) вам');
                        break;
                    }
                }
            }
        }
    }

    // Глобальный перехватчик клика для уведомлений чата
    document.addEventListener('click', function(e) {
        const target = e.target.closest('[role="button"]');
        if (!target) return;
        // Проверяем, что это уведомление с изменённым preview
        const previewEl = target.querySelector('p');
        if (!previewEl || previewEl.textContent.trim() !== '[вам написали]') return;

        e.preventDefault();
        e.stopImmediatePropagation();

        // Извлекаем username актора из ссылки на профиль
        const profileLink = target.querySelector('a[title="Перейти в профиль"]');
        if (!profileLink) return;
        const href = profileLink.getAttribute('href');
        const match = href?.match(/^\/@(.+)$/);
        if (!match) return;
        const username = match[1];

        // Ищем пользователя по username в данных чата
        if (window.НеЗнаюКакНазвать && window.НеЗнаюКакНазвать.пользователи) {
            const user = window.НеЗнаюКакНазвать.пользователи.find(u => u.имяПользователя === username);
            if (user && user.айди) {
                window.location.href = `https://xn--d1ah4a.com/@itd_chat/post/@${user.айди}`;
                return;
            }
        }
        // Если не найден – всё равно отменяем стандартное поведение
    }, true);

    // Запуск обработки текущих элементов и наблюдение за изменениями
    if (document.body) processNotificationElements();
    const notificationsObserver = new MutationObserver(() => {
        processNotificationElements();
    });
    notificationsObserver.observe(document.body, { childList: true, subtree: true });
})();
