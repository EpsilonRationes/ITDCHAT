(function() {
'use strict';

// Диффи-Хеллман на JavaScript с использованием Web Crypto API
class DiffieHellman {
    constructor() {
        this.privateKey = null;
        this.publicKey = null;
        this.sharedSecret = null;
    }

    // Генерация закрытого и открытого ключей
    async generateKeys() {
        const keyPair = await crypto.subtle.generateKey(
            {
                name: "ECDH",
                namedCurve: "P-256"
            },
            true,
            ["deriveKey", "deriveBits"]
        );

        this.privateKey = keyPair.privateKey;
        this.publicKey = keyPair.publicKey;
        
        return this.publicKey;
    }

    // Экспорт публичного ключа для отправки
    async exportPublicKey() {
        const exported = await crypto.subtle.exportKey(
            "spki",
            this.publicKey
        );
        return btoa(String.fromCharCode(...new Uint8Array(exported)));
    }

    // Импорт публичного ключа собеседника
    async importPublicKey(exportedKey) {
        const keyData = Uint8Array.from(atob(exportedKey), c => c.charCodeAt(0));
        
        return await crypto.subtle.importKey(
            "spki",
            keyData,
            {
                name: "ECDH",
                namedCurve: "P-256"
            },
            false,
            []
        );
    }

    // Вычисление общего ключа
    async computeSharedSecret(otherPublicKey) {
        otherPublicKey = await this.importPublicKey(otherPublicKey)
        this.sharedSecret = await crypto.subtle.deriveBits(
            {
                name: "ECDH",
                public: otherPublicKey
            },
            this.privateKey,
            256 
        );

        return this.sharedSecret;
    }

    uuidToSalt(uuid) {
        const cleanUuid = uuid.replace(/-/g, '');
        
        const salt = new Uint8Array(16);
        for (let i = 0; i < 32; i += 2) {
            salt[i/2] = parseInt(cleanUuid.substr(i, 2), 16);
        }
        
        return salt;
    }

    // HKDF для деривации ключа
    async deriveKey(uuid) {
        const salt = this.uuidToSalt(uuid);
        // Импортируем общий секрет как материал для HKDF
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            this.sharedSecret,
            "HKDF",
            false,
            ["deriveBits", "deriveKey"]
        );

        // Деривация ключа AES-256
        const aesKey = await crypto.subtle.deriveKey(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt: salt,
                info: new TextEncoder().encode("ITD-cross-tunel")
            },
            keyMaterial,
            { name: "AES-CTR", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );

        return aesKey;
    }
}

class MinimalCipher {
    constructor(aesKey) {
        this.key = aesKey;
        this.encoder = new TextEncoder();
        this.decoder = new TextDecoder();
    }


    async encrypt(plainText) {
        const data = this.encoder.encode(plainText);
        const nonce = crypto.getRandomValues(new Uint8Array(8));
        const counter = new Uint8Array(16);
        counter.set(nonce, 0);

        const encrypted = await crypto.subtle.encrypt(
            {
                name: "AES-CTR",
                counter: counter,
                length: 64
            },
            this.key,
            data
        );

        const result = new Uint8Array(nonce.length + encrypted.byteLength);
        result.set(nonce, 0);
        result.set(new Uint8Array(encrypted), nonce.length);
        
        return btoa(String.fromCharCode(...result));
    }


    async decrypt(encryptedBase64) {
        const encrypted = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
        
        const nonce = encrypted.slice(0, 8);
        const ciphertext = encrypted.slice(8);

        const counter = new Uint8Array(16);
        counter.set(nonce, 0);

        const decrypted = await crypto.subtle.decrypt(
            {
                name: "AES-CTR",
                counter: counter,
                length: 64
            },
            this.key,
            ciphertext
        );

        return this.decoder.decode(decrypted);
    }
}

// ckey to String
async function keyToStr(key) {
    const exportedKey = await crypto.subtle.exportKey("raw", key);
    return btoa(String.fromCharCode(...new Uint8Array(exportedKey)));
}

// ckey from String
async function strToKey(keyString) {
    const keyData = Uint8Array.from(atob(keyString), c => c.charCodeAt(0));
    return await crypto.subtle.importKey(
        "raw",
        keyData,
        { name: "AES-CTR" },
        true,
        ["encrypt", "decrypt"]
    );
}


const saveMeUUID = (value) => localStorage.setItem('myUUID', value);
const getMeUUID = () => localStorage.getItem('myUUID');
const saveCkeys = (data) => localStorage.setItem("ckeys", JSON.stringify(data));
const getCkeys = () => JSON.parse(localStorage.getItem("ckeys")) || {};

let messages = [];

async function injectSSEProxy() {
    const originalFetch = window.fetch;

    window.fetch = async function(...args) {
        const response = await originalFetch.apply(this, args);
        
        if (args[0].includes('/notifications/stream')) { 
            const originalBody = response.body;
            const reader = originalBody.getReader();

            const newStream = new ReadableStream({
                async start(controller) {
                    while (true) {
                        const { done, value } = await reader.read();
                        if (done) break;

                        controller.enqueue(await notificationHandler(value));

                        if (messages.length > 0) {
                            for (const message of messages) {
                                const value = new TextEncoder().encode(`event: notification\ndata: ${JSON.stringify(message)}\n\n`);
                                controller.enqueue(await notificationHandler(value));
                            }
                            messages = [];
                        }
                    }
                    controller.close();
                }
            });


            return new Response(newStream, {
                status: response.status,
                statusText: response.statusText,
                headers: response.headers
            });
        }
        
        return response;
    };
}

function send_message(message) {
    messages.push({
        id: "eda7d543-a8e8-4ee6-b8d9-0f6ae634feb4",
        type: "comment",
        targetType: "post",
        targetId: "eda7d543-a8e8-4ee6-b8d9-0f6ae634feb4",
        preview: message,
        readAt: null,
        createdAt: "2026-02-14T07:24:20.494Z",
        userId: "a52fcef6-d4de-4453-af62-fbc348d7d997",
        actor: {
            id:"331dea20-bb7c-4c96-ad09-97150f1ad5f6",
            "displayName": "ITD+",
            "username": "ITD+",
            "avatar": "+"
        },
        read: false,
        sound: true
    });
}
window.send_message = send_message;



function saveToken(token) {
    localStorage.setItem('access_token', token);
}


function getToken() {
    return localStorage.getItem('access_token');
}



const originalFetch = window.fetch;

async function fetchRefreshOn401(url, options = {}) {
    let accessToken = getToken();
    
    if (!accessToken) {
        const resRefresh = await originalFetch('/api/v1/auth/refresh', { method: 'POST' });
        const data = await resRefresh.json();
        accessToken = data.accessToken;
        if (!accessToken) return null;
        saveToken(accessToken);
    }

    let response = await originalFetch(url, {
        ...options,
        headers: {
            ...options.headers,
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
        }
    });

    if (response.status === 401) {
        const resRefresh = await originalFetch('/api/v1/auth/refresh', { method: 'POST' });
        const data = await resRefresh.json();
        accessToken = data.accessToken;
        if (!accessToken) return null;
        saveToken(accessToken);


        response = await originalFetch(url, {
            ...options,
            headers: {
                ...options.headers,
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            }
        });
    }

    return response;
}

// ======= Кодировние и декодирование сообщений ===========

const chipers = {};

async function update_chipers() {
    const ckeys = getCkeys();
    for (const postId in ckeys) {
        const ckey = ckeys[postId].ckey;
        if (typeof ckey != 'string') {continue}
        chipers[postId] = new MinimalCipher(await strToKey(ckey));
    }
}

function extractPostIdFromUrl(url) {
    const regex = /\/posts\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i;
    
    const match = url.match(regex);
    
    return match ? match[1] : null;
}

function extractMessageFromEncrypted(input) {
    const regex = /ITD-cross-tunel:mes\s+(.+)/;
    const match = input.match(regex);

    return match ? match[1] : null;
}

window.update_chipers = update_chipers;
window.chipers = chipers;
async function injectChiper() {
    const originalFetch = window.fetch;

    window.fetch = async function(...args) {
        const postId = extractPostIdFromUrl(args[0]);
        if (postId) {
            let originalContent = "";
            if (Object.keys(chipers).length == 0) {
                await update_chipers();
            }
            if (args[0].includes("comments") && postId in chipers && args[1].method == "POST") {
                const body = JSON.parse(args[1].body);
                originalContent = body.content;
                const encripted = await chipers[postId].encrypt(body.content)
                body.content = "ITD-cross-tunel:mes\n" + encripted;
                args[1].body = JSON.stringify(body);
            }

            const response = await originalFetch.apply(this, args);
            const root = await response.json();

            if (args[1].method == "POST" && args[0].includes("comments")) {
                if (originalContent.length > 0) {
                    root.content = originalContent;
                }
            } else if (args[1].method == "GET") {
                root.data.comments = await Promise.all(root.data.comments.map(async (comment) => {
                    const mes = extractMessageFromEncrypted(comment.content);
                    if (mes) { 
                        try{
                            comment.content = await chipers[postId].decrypt(mes);
                            return comment;
                        } catch (err) {}
                    }
                    return comment;
                }))
            }

            return new Response(JSON.stringify(root), { status: response.status, headers: response.headers });
        }
        
        return await originalFetch.apply(this, args);
    }
}


// ========= Создание чата ===========

function getRegComment() {
    return localStorage.getItem('regComment');
}

function saveRegComment(value) {
    localStorage.setItem('regComment', value);
}

const REGISTRATION_POST_ID = "9b9b2283-e664-4322-b37f-4aa3ee20c2d1";
const CHAT_STORAGE_WALL = "959127ba-f2f7-4e03-adba-f67ee4ff3a93";


async function registation() {
    if (!getRegComment()) {
        const response = await fetchRefreshOn401(`/api/posts/${REGISTRATION_POST_ID}/comments`, {
            method: "POST",
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({content: "ITD-cross-tunel:reg"})
        });
        if (response.status != 201) {
            send_message("Ошибка регистрации");
            return;
        }
        const data = await response.json();
        saveRegComment(data.id);
    }   
}

async function fetchUserRegistrationComment(user_uuid) {
    let cursor = null;

    while (true) {
        const response = await fetchRefreshOn401(
            `/api/posts/${REGISTRATION_POST_ID}/comments?limit=50&sort=newest` + (cursor ? "&cursor="+cursor : ""),
            {method: "GET"}
        )
        const data = (await response.json()).data;
        
        for (const comment of data.comments) {
            if (comment.author.id == user_uuid) {
                return comment.id;
            }
        }

        cursor = data.nextCursor;
        if (cursor == null) {
            break;
        }

    }
    return null;
}

function getOpenKeyFromContent(content) {
    const keyPattern = /open_keyB\n(.+)/;
    const match = content.match(keyPattern);
    
    return match ? match[1] : null;
}

function getPostIdFromNotification(content) {
    const keyPattern = /"ITDCT:([^"]+)"/;
    const match = content.match(keyPattern);
    
    return match ? match[1] : null;
}

async function searchKeyB(postId, userUUID) {
    const response = await fetchRefreshOn401(
        `/api/posts/${postId}/comments?limit=50&sort=newest`,
        {method: "GET"}
    )
    const data = (await response.json()).data;
    
    for (const comment of data.comments) {
        const key = getOpenKeyFromContent(comment.content)
        if (comment.author.id == userUUID && key) {
            return {comment: comment,keyB: key};
        }
    }
    return null;
}

async function initChat(me_uuid, user_uuid) {
    if (!getRegComment()) {
        await registation();
    }
    const userRegComment = await fetchUserRegistrationComment(user_uuid);
    if (!userRegComment) {
        send_message("Пользователь не зарестрирован");
        return;
    }
    
    const response = await fetchRefreshOn401(`/api/posts`, {
        method: "POST",
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            content: `ITD-cross-tunel:chat\n${me_uuid}\n${user_uuid}`, 
            wallRecipientId: CHAT_STORAGE_WALL
        })
    });
    if (response.status != 201) {
        send_message("Ошибка создания поста");
        return;
    }
    const data = await response.json();
    const postId = data.id;


    const keys = new DiffieHellman();
    await keys.generateKeys();
    const my_open_key = await keys.exportPublicKey();
    
    const responseComment = await fetchRefreshOn401(`/api/posts/${postId}/comments`, {
            method: "POST",
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({content: `ITD-cross-tunel:open_keyA\n${my_open_key}`})
        });
    if (responseComment.status != 201) {
        send_message("Ошибка создания комментария с ключом");
        return;
    }

    const responseNotification = await fetchRefreshOn401(`/api/comments/${userRegComment}/replies`, {
            method: "POST",
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({content: `ITDCT:${postId}`})
        });
    if (responseNotification.status != 201) {
        send_message("Ошибка создания комментария сообщения");
        return;
    }

    if (me_uuid == user_uuid) {
        send_message(`ITDCT:${postId}`);
    }

    send_message("Ожидание ответа пользователя номер 2");

    await new Promise(resolve => setTimeout(resolve, 60000));

    const {comment, keyB} = await searchKeyB(postId, user_uuid);

    if (!keyB) {
        send_message("Пользователь номер 2, не ответил");
        return;
    }

    await keys.computeSharedSecret(keyB); 
    const ckey = await keys.deriveKey(postId); 
    
    send_message("Чат создан A");

    const ckeys = getCkeys();
    ckeys[postId] = {
        ckey: await keyToStr(ckey),
        avatar: comment.author.avatar, 
        name: comment.author.displayName,
        username: comment.author.username
        
    }
    saveCkeys(ckeys);
    await update_chipers();
}

function extractIdsFromContent(content) {
    const pattern = /^ITD-cross-tunel:chat\n([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\n([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;
    
    const match = content.match(pattern);
    
    if (!match) {
        return null; 
    }    
    return {firstId: match[1], secondId: match[2]};
}

function getOpenKeyAFromContent(content) {
    const keyPattern = /open_keyA\n(.+)/;
    const match = content.match(keyPattern);
    
    return match ? match[1] : null;
}

async function searchKeyA(postId, userUUID) {
    const response = await fetchRefreshOn401(
        `/api/posts/${postId}/comments?limit=50&sort=newest`,
        {method: "GET"}
    )
    const data = (await response.json()).data;
    
    for (const comment of data.comments) {
        const key = getOpenKeyAFromContent(comment.content)
        if (comment.author.id == userUUID && key) {
            return {comment: comment, keyA: key};
        }
    }
    return null;
}

async function joyToChat(postId, meUUID) {
    const response = await fetchRefreshOn401(
        `/api/posts/${postId}`,
        {method: "GET"}
    )
    const data = (await response.json()).data;
    const content = data.content;
    const {firstId, secondId} = extractIdsFromContent(content);
    if (secondId != meUUID) {
        return; 
    }

    const {comment, keyA} = await searchKeyA(postId, firstId);
    if (!keyA) {
        send_message("Ключ не найден");
        return;
    }
    
    const keys = new DiffieHellman();
    await keys.generateKeys();
    const my_open_key = await keys.exportPublicKey();
    
    const responseComment = await fetchRefreshOn401(`/api/posts/${postId}/comments`, {
            method: "POST",
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({content: `ITD-cross-tunel:open_keyB\n${my_open_key}`})
        });
    if (responseComment.status != 201) {
        send_message("Ошибка создания комментария с ключом");
        return;
    }

    await keys.computeSharedSecret(keyA); 
    const ckey = await keys.deriveKey(postId); 
    
    send_message("Чат создан B");

    const ckeys = getCkeys();
    ckeys[postId] = {
        ckey: await keyToStr(ckey),
        avatar: comment.author.avatar, 
        name: comment.author.displayName,
        username: comment.author.username
        
    }
    saveCkeys(ckeys);
    await update_chipers();
}

function getUserIdFromConnected(message) {
    const regex = /^event:\s*connected\s*\ndata:\s*\{\s*"userId"\s*:\s*"([a-f0-9-]+)"\s*,\s*"timestamp"\s*:\s*\d+\s*\}\s*$/i;
    
    const match = message.match(regex);
    
    if (match) {
        return match[1]
    } else {
        return null;
    }
}

async function notificationHandler(message) {
    message = new TextDecoder().decode(message);
    const userId = getUserIdFromConnected(message);
    if (userId) {
        saveMeUUID(userId);
    }

    const postId = getPostIdFromNotification(message)
    if (postId) {
        await joyToChat(postId, getMeUUID());
    }

    return new TextEncoder().encode(message);
}




// ========= UI =========
let last_user_id = '';
function getUsernameFromPath(path) {
    const match = path.match(/\/api\/users\/([^/]+)$/);
    return match ? match[1] : null;
}   

async function injectNotifications() {
    const originalFetch = window.fetch;

    window.fetch = async function(...args) {
        const response = await originalFetch.apply(this, args);
        
        if (args[0].includes("/api/notifications/?offset=0")) {
            const root = await response.json();
            const chats = getCkeys();
            let i = 0;
            for (const postId in chats){
                ++i;
                const chat = chats[postId];
                if (typeof chat == 'string' || Object.keys(chat).length == 0) {continue}
                const notification = {
                    actor: {
                        id: "93252a51-a0ea-4401-88ea-fa3fc104270d", 
                        displayName: chat.displayName, 
                        username: chat.username, 
                        avatar: chat.avatar,
                    },

                    createdAt: "2026-02-13T03:53:46.780Z",
                    id: '@' + postId,
                    preview: i + chat.username,
                    read: true,
                    readAt: "2026-02-13T04:43:21.162Z",
                    targetId: postId,
                    targetType: "post",
                    type: "reply"
                }
                root.notifications.push(notification);
            } 
            
            return new Response(JSON.stringify(root), { status: response.status, headers: response.headers });
        }

        const username = getUsernameFromPath(args[0]);
        if (username) {
            const data = await response.json();
            last_user_id = data.id; 
            return new Response(JSON.stringify(data), { status: response.status, headers: response.headers });
        }

        return response;
    }
}



const observer = new MutationObserver(() => {
    const mentionsBtn = document.querySelector(".notifications-tabs :nth-child(2)");
    if (mentionsBtn != null) {
        if (!mentionsBtn.dataset.init) {
            mentionsBtn.innerHTML = "Чаты";
            mentionsBtn.dataset.init = 'true';
        }
    }

    const notificationsList = document.querySelector(".notifications-list");
    if (notificationsList && !notificationsList.dataset.itd) {
        const tab = document.querySelector(".notifications-tabs .active:nth-child(2)")
        if (tab) {
            const notifications = notificationsList.querySelectorAll(".notification-item");
            notifications.forEach((element) => {
                if (element.dataset.itd) {return}
                
                if (element.dataset.notificationId[0] != '@') {
                    element.style.display = 'none';
                    element.dataset.itd = "true";
                } else {
                    element.querySelector(".notification-badge").style.display = 'none';
                    element.querySelector(".notification-action").style.display = 'none';
                    element.querySelector('.notification-time').style.display = 'none';
                }
            })

            if (window.location.pathname == "/notifications") {
                const post = document.querySelector(".post-modal-backdrop");
                if (post && !post.dataset.itd) {
                    const header = post.querySelector(".post-modal__header");
                    if (header) {
                        //post.innerHTML += "<style>.comment-submit--mic {display: none;}</style>"; 
                        header.style.display = 'none';
                        post.querySelector(".post-modal__text").style.display = 'none';
                        post.querySelector(".post-modal__actions").style.display = 'none';
                        post.querySelector(".comments-sort").style.display = 'none';
                        post.querySelector(".comment-attach-btn").style.display = 'none';
                        post.querySelector(".comment-submit").style.display = 'none';
                        const textarea = post.querySelector('.comment-input-field');
                        textarea.placeholder = 'Написапить сообщение...';
                        textarea.addEventListener('input', () => {
                            if (textarea.value.length == 0) {
                                
                                setTimeout(() => post.querySelector(".comment-submit--mic").style.display = 'none', 10);
                            }
                        })
                        post.dataset.itd = 'true';
                    }
                }

                if (post) {
                    const comments = post.querySelectorAll(".comment");
                    comments.forEach((element) => {
                        if (!element.dataset.itd) {
                            const actions = element.querySelector(".item-actions")
                            if (actions) {
                                actions.style.display = 'none';
                                element.dataset.itd = "true";
                            }
                        }
                    })
                }
            }
        }
    }
    
    

    const profileActions = document.querySelector(".profile-action__buttons") || document.querySelector(".profile-own-actions");;

    if (profileActions && !profileActions.dataset.itd) {
        profileActions.dataset.itd = 'true';
        profileActions.insertAdjacentHTML('afterbegin', 
        '<button class="profile-follow-btn chat-btn svelte-p40znu">Создать чат</button>'
        );
        const chatBtn = profileActions.querySelector('.chat-btn');
        chatBtn.addEventListener('click', () => {
            chatBtn.classList.add("following")
            chatBtn.disabled = true;
            initChat(getMeUUID(), last_user_id);
        }) 
    }

    
}) 

window.initChatModule = () => {
    injectChiper().then((data) => {});
    window.initChat = (user_uuid) => initChat(getMeUUID(), user_uuid);
    injectSSEProxy().then(() => {})
    injectNotifications().then(() => {})
    observer.observe(document.body, { childList: true, subtree: true });
}


})();

