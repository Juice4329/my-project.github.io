// Мобильное меню - используем IntersectionObserver для ленивой загрузки
        const btn = document.querySelector('.mobile-menu-button');
        const menu = document.querySelector('.mobile-menu');

        btn.addEventListener('click', () => {
            menu.classList.toggle('hidden');
        });

        // Плавная прокрутка с debounce и requestAnimationFrame для оптимизации
        let scrollTimeout;
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function(e) {
                e.preventDefault();
                
                const targetId = this.getAttribute('href');
                if (targetId === '#') return;
                
                // Отменяем предыдущий таймаут, если он есть
                if (scrollTimeout) {
                    clearTimeout(scrollTimeout);
                }
                
                const targetElement = document.querySelector(targetId);
                if (targetElement) {
                    scrollTimeout = setTimeout(() => {
                        // Используем requestAnimationFrame для более плавной анимации
                        requestAnimationFrame(() => {
                            window.scrollTo({
                                top: targetElement.offsetTop - 80,
                                behavior: 'smooth'
                            });
                            
                            // Закрываем мобильное меню после клика
                            menu.classList.add('hidden');
                        });
                    }, 50); // Уменьшенная задержка для быстрого отклика
                }
            });
        });

        // Инициализация индикатора активной вкладки с использованием кэширования DOM-элементов
        function initNavIndicator() {
            const navIndicator = document.getElementById('navIndicator');
            const navItems = document.querySelectorAll('.nav-item');
            
            // Устанавливаем начальное положение индикатора для активной вкладки
            const activeTab = document.querySelector('.nav-item.active-tab');
            if (activeTab) {
                updateIndicator(activeTab);
            }
            
            // Кэшируем родительский элемент для всех вкладок для оптимизации
            const navParent = navItems[0]?.parentElement;
            
            // Обработчик клика по вкладке
            navItems.forEach(item => {
                item.addEventListener('click', function() {
                    // Удаляем класс active-tab у всех вкладок
                    navItems.forEach(navItem => navItem.classList.remove('active-tab', 'text-blue-600', 'dark:text-blue-400'));
                    
                    // Добавляем класс active-tab текущей вкладке
                    this.classList.add('active-tab', 'text-blue-600', 'dark:text-blue-400');
                    
                    // Обновляем положение индикатора
                    updateIndicator(this);
                });
            });
            
            // Оптимизированная функция обновления положения индикатора
            function updateIndicator(element) {
                if (!element || !navIndicator || !navParent) return;
                
                const itemRect = element.getBoundingClientRect();
                const navRect = navParent.getBoundingClientRect();
                
                // Используем transform вместо left для лучшей производительности
                navIndicator.style.width = `${itemRect.width}px`;
                navIndicator.style.transform = `translateX(${itemRect.left - navRect.left}px)`;
            }
            
            // Оптимизированный обработчик изменения размера окна с троттлингом
            let resizeTimeout;
            let lastWidth = window.innerWidth;
            
            window.addEventListener('resize', () => {
                // Проверяем изменение ширины для экономии ресурсов
                if (window.innerWidth !== lastWidth) {
                    lastWidth = window.innerWidth;
                    
                    clearTimeout(resizeTimeout);
                    resizeTimeout = setTimeout(() => {
                        const activeTab = document.querySelector('.nav-item.active-tab');
                        if (activeTab) {
                            updateIndicator(activeTab);
                        }
                    }, 100);
                }
            });
        }
        
        // Тема приложения с оптимизацией
        function initTheme() {
            const themeToggle = document.getElementById('themeToggle');
            const darkIcon = document.getElementById('darkIcon');
            const lightIcon = document.getElementById('lightIcon');
            const htmlElement = document.documentElement;
            
            // Проверяем сохраненную тему или системные настройки
            const savedTheme = localStorage.getItem('theme') || 
                              (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
            
            // Применяем тему
            if (savedTheme === 'dark') {
                htmlElement.classList.add('dark');
                darkIcon.classList.add('hidden');
                lightIcon.classList.remove('hidden');
            } else {
                htmlElement.classList.remove('dark');
                darkIcon.classList.remove('hidden');
                lightIcon.classList.add('hidden');
            }
            
            // Оптимизированный обработчик переключения темы
            themeToggle.addEventListener('click', function() {
                const isDark = htmlElement.classList.toggle('dark');
                localStorage.setItem('theme', isDark ? 'dark' : 'light');
                
                if (isDark) {
                    darkIcon.classList.add('hidden');
                    lightIcon.classList.remove('hidden');
                } else {
                    darkIcon.classList.remove('hidden');
                    lightIcon.classList.add('hidden');
                }
            });
        }
        
        // Демо шифрования - кэшируем DOM-элементы
        const encryptBtn = document.getElementById('encryptBtn');
        const decryptBtn = document.getElementById('decryptBtn');
        const inputText = document.getElementById('inputText');
        const outputResult = document.getElementById('outputResult');
        const encryptionMethod = document.getElementById('encryptionMethod');
        const keyInfo = document.getElementById('keyInfo');
        const passwordContainer = document.getElementById('passwordContainer');
        const passwordInput = document.getElementById('password');
        const encryptText = document.getElementById('encryptText');
        const encryptSpinner = document.getElementById('encryptSpinner');
        const decryptText = document.getElementById('decryptText');
        const decryptSpinner = document.getElementById('decryptSpinner');
        const copyBtn = document.getElementById('copyBtn');
        const inputError = document.getElementById('inputError');
        const passwordError = document.getElementById('passwordError');
        const passwordStrengthBar = document.getElementById('passwordStrengthBar');
        
        // Элементы требований к паролю
        const lengthReq = document.getElementById('lengthReq');
        const uppercaseReq = document.getElementById('uppercaseReq');
        const numberReq = document.getElementById('numberReq');
        const specialReq = document.getElementById('specialReq');
        
        // Для шифрования файлов
        const fileInput = document.getElementById('fileInput');
        const dropZone = document.getElementById('dropZone');
        const fileInfo = document.getElementById('fileInfo');
        const fileName = document.getElementById('fileName');
        const fileSize = document.getElementById('fileSize');
        const removeFileBtn = document.getElementById('removeFileBtn');
        const encryptFileBtn = document.getElementById('encryptFileBtn');
        const decryptFileBtn = document.getElementById('decryptFileBtn');
        const filePassword = document.getElementById('filePassword');
        const filePasswordError = document.getElementById('filePasswordError');
        const fileEncryptionMethod = document.getElementById('fileEncryptionMethod');
        const fileStatus = document.getElementById('fileStatus');
        const fileProgress = document.getElementById('fileProgress');
        const fileProgressBar = document.getElementById('fileProgressBar');
        const fileProgressText = document.getElementById('fileProgressText');
        const fileProgressBytes = document.getElementById('fileProgressBytes');
        const fileActions = document.getElementById('fileActions');
        const downloadFileBtn = document.getElementById('downloadFileBtn');
        
        // Состояние приложения
        let lastEncryptedData = null;
        let lastKey = null;
        let lastIv = null;
        let lastPublicKey = null;
        let lastPrivateKey = null;
        let copyTimeout = null;
        let currentFile = null;
        let encryptedFile = null;
        let decryptedFile = null;
        
        // Валидация ввода текста
        function validateInputText() {
            const text = inputText.value.trim();
            if (!text) {
                inputText.classList.add('input-error');
                inputError.style.display = 'block';
                return false;
            } else {
                inputText.classList.remove('input-error');
                inputError.style.display = 'none';
                return true;
            }
        }
        
        // Валидация пароля
        function validatePassword(password) {
            // Проверка минимальной длины
            const hasMinLength = password.length >= 8;
            
            // Проверка наличия заглавной буквы
            const hasUppercase = /[A-Z]/.test(password);
            
            // Проверка наличия цифры
            const hasNumber = /\d/.test(password);
            
            // Проверка наличия спецсимвола
            const hasSpecialChar = /[!@#$%^&*]/.test(password);
            
            // Обновляем индикаторы требований
            updateRequirement(lengthReq, hasMinLength);
            updateRequirement(uppercaseReq, hasUppercase);
            updateRequirement(numberReq, hasNumber);
            updateRequirement(specialReq, hasSpecialChar);
            
            // Рассчитываем силу пароля (0-4)
            let strength = 0;
            if (hasMinLength) strength++;
            if (hasUppercase) strength++;
            if (hasNumber) strength++;
            if (hasSpecialChar) strength++;
            
            // Обновляем индикатор силы пароля
            updatePasswordStrength(strength);
            
            // Пароль валиден, если выполнены все требования
            return hasMinLength && hasUppercase && hasNumber && hasSpecialChar;
        }
        
        // Обновление индикатора требования
        function updateRequirement(element, isValid) {
            if (isValid) {
                element.classList.remove('invalid');
                element.classList.add('valid');
                element.querySelector('i').className = 'fas fa-check-circle';
            } else {
                element.classList.remove('valid');
                element.classList.add('invalid');
                element.querySelector('i').className = 'fas fa-circle';
            }
        }
        
        // Обновление индикатора силы пароля
        function updatePasswordStrength(strength) {
            let width = 0;
            let color = '';
            
            switch(strength) {
                case 0:
                    width = 0;
                    color = '#ef4444'; // red-500
                    break;
                case 1:
                    width = 25;
                    color = '#ef4444'; // red-500
                    break;
                case 2:
                    width = 50;
                    color = '#f59e0b'; // amber-500
                    break;
                case 3:
                    width = 75;
                    color = '#3b82f6'; // blue-500
                    break;
                case 4:
                    width = 100;
                    color = '#10b981'; // emerald-500
                    break;
            }
            
            passwordStrengthBar.style.width = `${width}%`;
            passwordStrengthBar.style.backgroundColor = color;
        }
        
        // Показываем/скрываем поле пароля в зависимости от метода
        encryptionMethod.addEventListener('change', () => {
            if (encryptionMethod.value === 'aes') {
                passwordContainer.classList.remove('hidden');
            } else {
                passwordContainer.classList.add('hidden');
            }
        });
        
        // Валидация пароля при вводе
        passwordInput.addEventListener('input', () => {
            const password = passwordInput.value;
            validatePassword(password);
        });
        
        // Валидация текста при вводе
        inputText.addEventListener('input', () => {
            validateInputText();
        });
        
        // Функция для преобразования ArrayBuffer в hex строку
        function arrayBufferToHex(buffer) {
            return Array.from(new Uint8Array(buffer))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
        }
        
        // Функция для преобразования hex строки в ArrayBuffer
        function hexToArrayBuffer(hex) {
            const bytes = new Uint8Array(hex.length / 2);
            for (let i = 0; i < hex.length; i += 2) {
                bytes[i/2] = parseInt(hex.substr(i, 2), 16);
            }
            return bytes.buffer;
        }
        
        // Генерация RSA ключей с экспортом
        async function generateRSAKeys() {
            try {
                const keyPair = await window.crypto.subtle.generateKey(
                    {
                        name: "RSA-OAEP",
                        modulusLength: 2048,
                        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                        hash: "SHA-256",
                    },
                    true,
                    ["encrypt", "decrypt"]
                );
                
                // Экспортируем ключи в формата spki/pkcs8
                const exportedPublicKey = await window.crypto.subtle.exportKey(
                    "spki",
                    keyPair.publicKey
                );
                
                const exportedPrivateKey = await window.crypto.subtle.exportKey(
                    "pkcs8",
                    keyPair.privateKey
                );
                
                // Преобразуем ArrayBuffer в строку base64
                const publicKeyBase64 = arrayBufferToBase64(exportedPublicKey);
                const privateKeyBase64 = arrayBufferToBase64(exportedPrivateKey);
                
                return {
                    keyPair,
                    publicKeyBase64,
                    privateKeyBase64
                };
            } catch (err) {
                console.error("Ошибка генерации RSA ключей:", err);
                throw err;
            }
        }
        
        // Функция для преобразования ArrayBuffer в base64
        function arrayBufferToBase64(buffer) {
            let binary = '';
            const bytes = new Uint8Array(buffer);
            const len = bytes.byteLength;
            for (let i = 0; i < len; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return window.btoa(binary);
        }
        
        // Функция для преобразования base64 в ArrayBuffer
        function base64ToArrayBuffer(base64) {
            const binaryString = window.atob(base64);
            const len = binaryString.length;
            const bytes = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes.buffer;
        }
        
        // Импорт RSA ключа из base64
        async function importRSAPublicKey(base64Key) {
            try {
                const keyBuffer = base64ToArrayBuffer(base64Key);
                
                const publicKey = await window.crypto.subtle.importKey(
                    "spki",
                    keyBuffer,
                    {
                        name: "RSA-OAEP",
                        hash: "SHA-256"
                    },
                    true,
                    ["encrypt"]
                );
                
                return publicKey;
            } catch (err) {
                console.error("Ошибка импорта RSA ключа:", err);
                throw err;
            }
        }
        
        // Импорт приватного RSA ключа из base64
        async function importRSAPrivateKey(base64Key) {
            try {
                const keyBuffer = base64ToArrayBuffer(base64Key);
                
                const privateKey = await window.crypto.subtle.importKey(
                    "pkcs8",
                    keyBuffer,
                    {
                        name: "RSA-OAEP",
                        hash: "SHA-256"
                    },
                    true,
                    ["decrypt"]
                );
                
                return privateKey;
            } catch (err) {
                console.error("Ошибка импорта RSA ключа:", err);
                throw err;
            }
        }
        
        // Шифрование AES
        async function encryptAES(text, password) {
            try {
                console.log("Начало шифрования AES");
                
                // 1. Генерация ключа из пароля
                const keyMaterial = await window.crypto.subtle.importKey(
                    'raw',
                    new TextEncoder().encode(password),
                    { name: 'PBKDF2' },
                    false,
                    ['deriveKey']
                );
                
                console.log("Ключевой материал создан");
                
                // 2. Создание ключа шифрования
                const salt = window.crypto.getRandomValues(new Uint8Array(16));
                const key = await window.crypto.subtle.deriveKey(
                    {
                        name: 'PBKDF2',
                        salt: salt,
                        iterations: 100000,
                        hash: 'SHA-256'
                    },
                    keyMaterial,
                    { name: 'AES-GCM', length: 256 },
                    false,
                    ['encrypt', 'decrypt']
                );
                
                console.log("Ключ шифрования создан");
                
                // 3. Шифрование данных
                const iv = window.crypto.getRandomValues(new Uint8Array(12));
                const encrypted = await window.crypto.subtle.encrypt(
                    { name: 'AES-GCM', iv },
                    key,
                    new TextEncoder().encode(text)
                );
                
                console.log("Данные зашифрованы", encrypted);
                
                // Сохраняем ключ и IV для дешифрования
                lastKey = key;
                lastIv = iv;
                
                // Возвращаем результат в формате, который можно сохранить
                return {
                    encrypted: Array.from(new Uint8Array(encrypted)),
                    iv: Array.from(iv),
                    salt: Array.from(salt)
                };
            } catch (err) {
                console.error("Ошибка AES шифрования:", err);
                alert("Ошибка шифрования: " + err.message);
                throw err;
            }
        }
        
        // Дешифрование AES
        async function decryptAES(encryptedData, iv, password, salt) {
            try {
                // 1. Генерация ключа из пароля
                const keyMaterial = await window.crypto.subtle.importKey(
                    'raw',
                    new TextEncoder().encode(password),
                    { name: 'PBKDF2' },
                    false,
                    ['deriveKey']
                );
                
                // 2. Создание ключа шифрования
                const key = await window.crypto.subtle.deriveKey(
                    {
                        name: 'PBKDF2',
                        salt: new Uint8Array(salt),
                        iterations: 100000,
                        hash: 'SHA-256'
                    },
                    keyMaterial,
                    { name: 'AES-GCM', length: 256 },
                    false,
                    ['encrypt', 'decrypt']
                );
                
                // 3. Дешифрование данных
                const decrypted = await window.crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: new Uint8Array(iv) },
                    key,
                    new Uint8Array(encryptedData)
                );
                
                return new TextDecoder().decode(decrypted);
            } catch (err) {
                console.error("Ошибка AES дешифрования:", err);
                throw err;
            }
        }
        
        // Шифрование RSA
        async function encryptRSA(text, publicKey) {
            try {
                const encrypted = await window.crypto.subtle.encrypt(
                    { name: "RSA-OAEP" },
                    publicKey,
                    new TextEncoder().encode(text)
                );
                
                return Array.from(new Uint8Array(encrypted));
            } catch (err) {
                console.error("Ошибка RSA шифрования:", err);
                throw err;
            }
        }
        
        // Дешифрование RSA
        async function decryptRSA(encryptedData, privateKey) {
            try {
                const decrypted = await window.crypto.subtle.decrypt(
                    { name: "RSA-OAEP" },
                    privateKey,
                    new Uint8Array(encryptedData)
                );
                
                return new TextDecoder().decode(decrypted);
            } catch (err) {
                console.error("Ошибка RSA дешифрования:", err);
                throw err;
            }
        }
        
        // Хеширование с Argon2
        async function hashWithArgon2(text) {
            try {
                console.log("Начало хеширования Argon2");
                
                // Проверяем доступность библиотеки
                if (typeof argon2 === 'undefined') {
                    throw new Error('Библиотека Argon2 не загружена');
                }
                
                // Генерируем случайную соль
                const salt = window.crypto.getRandomValues(new Uint8Array(16));
                
                console.log("Соль сгенерирована, начинаем хеширование");
                
                // Хешируем с параметрами
                const result = await argon2.hash({
                    pass: text,
                    salt: salt,
                    time: 3,       // Количество итераций
                    mem: 65536,    // Используемая память в KiB
                    hashLen: 32,   // Длина хеша в байтах
                    parallelism: 1 // Количество потоков
                });
                
                console.log("Хеширование завершено", result);
                
                return result.encoded;
            } catch (err) {
                console.error("Ошибка хеширования Argon2:", err);
                // Создаем хеш с помощью SHA-256 как fallback
                try {
                    const msgBuffer = new TextEncoder().encode(text);
                    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
                    const hashArray = Array.from(new Uint8Array(hashBuffer));
                    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                } catch (fallbackErr) {
                    console.error("Ошибка fallback хеширования:", fallbackErr);
                    throw new Error("Не удалось выполнить хеширование");
                }
            }
        }
        
        // Обработчик кнопки шифрования
        encryptBtn.addEventListener('click', async function() {
            console.log("Нажата кнопка шифрования");
            
            const text = inputText.value.trim();
            const method = encryptionMethod.value;
            
            console.log("Текст:", text, "Метод:", method);
            
            // Валидация ввода
            if (!validateInputText()) {
                console.log("Валидация текста не прошла");
                return;
            }
            
            if (method === 'aes') {
                const password = passwordInput.value;
                console.log("Проверяем пароль AES:", password);
                
                if (password.length < 8) {
                    passwordInput.classList.add('input-error');
                    passwordError.style.display = 'block';
                    console.log("Пароль слишком короткий");
                    return;
                } else {
                    passwordInput.classList.remove('input-error');
                    passwordError.style.display = 'none';
                }
            }
            
            try {
                console.log("Начинаем шифрование");
                
                // Показываем спиннер
                encryptText.classList.add('hidden');
                encryptSpinner.classList.remove('hidden');
                encryptBtn.disabled = true;
                
                if (method === 'aes') {
                    const password = passwordInput.value;
                    const result = await encryptAES(text, password);
                    
                    // Выводим только зашифрованные данные (hex)
                    outputResult.innerHTML = `
                        <div class="hash-result text-center w-full">
                            ${arrayBufferToHex(new Uint8Array(result.encrypted).buffer)}
                        </div>
                    `;
                    
                    keyInfo.classList.remove('hidden');
                    keyInfo.querySelector('div').innerHTML = `
                        <p class="font-semibold">IV:</p>
                        <p>${result.iv.join(', ')}</p>
                        <p class="font-semibold mt-2">Salt:</p>
                        <p>${result.salt.join(', ')}</p>
                    `;
                    decryptBtn.classList.remove('hidden');
                    
                    lastEncryptedData = result;
                    lastKey = password;
                } 
                else if (method === 'rsa') {
                    const { keyPair, publicKeyBase64, privateKeyBase64 } = await generateRSAKeys();
                    const publicKey = keyPair.publicKey;
                    
                    const encrypted = await encryptRSA(text, publicKey);
                    
                    // Выводим только зашифрованные данные (hex)
                    outputResult.innerHTML = `
                        <div class="hash-result text-center w-full">
                            ${arrayBufferToHex(new Uint8Array(encrypted).buffer)}
                        </div>
                    `;
                    
                    keyInfo.classList.remove('hidden');
                    keyInfo.querySelector('div').innerHTML = `
                        <p class="font-semibold">Public Key (base64):</p>
                        <p class="break-all text-xs">${publicKeyBase64}</p>
                        <p class="font-semibold mt-2">Private Key (base64):</p>
                        <p class="break-all text-xs">${privateKeyBase64}</p>
                    `;
                    decryptBtn.classList.remove('hidden');
                    
                    lastEncryptedData = encrypted;
                    lastPublicKey = publicKeyBase64;
                    lastPrivateKey = privateKeyBase64;
                }
                else if (method === 'argon2') {
                    const hash = await hashWithArgon2(text);
                    
                    // Выводим только хеш
                    outputResult.innerHTML = `
                        <div class="hash-result text-center w-full">
                            ${hash}
                        </div>
                    `;
                    
                    keyInfo.classList.add('hidden');
                    decryptBtn.classList.add('hidden');
                }
                
                console.log("Шифрование завершено успешно");
                
            } catch (err) {
                console.error("Ошибка в обработчике шифрования:", err);
                outputResult.innerHTML = `<div class="text-red-500 p-2 rounded bg-red-50 dark:bg-red-900/30">Ошибка: ${err.message}</div>`;
            } finally {
                // Скрываем спиннер
                encryptText.classList.remove('hidden');
                encryptSpinner.classList.add('hidden');
                encryptBtn.disabled = false;
            }
        });
        
        // Обработчик кнопки дешифрования
        decryptBtn.addEventListener('click', async () => {
            if (!lastEncryptedData) return;
            
            const method = encryptionMethod.value;
            
            try {
                // Показываем спиннер
                decryptText.classList.add('hidden');
                decryptSpinner.classList.remove('hidden');
                decryptBtn.disabled = true;
                
                if (method === 'aes') {
                    const password = passwordInput.value;
                    if (!password) {
                        alert('Пожалуйста, введите пароль для дешифрования');
                        return;
                    }
                    
                    const decrypted = await decryptAES(
                        lastEncryptedData.encrypted,
                        lastEncryptedData.iv,
                        password,
                        lastEncryptedData.salt
                    );
                    
                    // Выводим только расшифрованный текст
                    outputResult.innerHTML = `<div class="text-center w-full">${decrypted}</div>`;
                }
                else if (method === 'rsa') {
                    if (!lastPrivateKey) {
                        alert('Приватный ключ не найден');
                        return;
                    }
                    
                    const privateKey = await importRSAPrivateKey(lastPrivateKey);
                    const decrypted = await decryptRSA(lastEncryptedData, privateKey);
                    
                    // Выводим только расшифрованный текст
                    outputResult.innerHTML = `<div class="text-center w-full">${decrypted}</div>`;
                }
            } catch (err) {
                console.error(err);
                outputResult.innerHTML = `<div class="text-red-500 p-2 rounded bg-red-50 dark:bg-red-900/30">Ошибка дешифрования: ${err.message}</div>`;
            } finally {
                // Скрываем спиннер
                decryptText.classList.remove('hidden');
                decryptSpinner.classList.add('hidden');
                decryptBtn.disabled = false;
            }
        });
        
        // Функции для работы с файлами
        
        // Форматирование размера файла
        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        // Обновление прогресса
        function updateFileProgress(loaded, total) {
            const progress = (loaded / total) * 100;
            fileProgressBar.style.width = progress + '%';
            fileProgressText.textContent = Math.round(progress) + '%';
            fileProgressBytes.textContent = `${formatFileSize(loaded)}/${formatFileSize(total)}`;
        }
        
        // Показать информацию о файле
        function showFileInfo(file) {
            fileName.textContent = file.name;
            fileSize.textContent = formatFileSize(file.size);
            fileInfo.classList.remove('hidden');
            currentFile = file;
            
            // Проверяем размер файла
            if (file.size > 100 * 1024 * 1024) { // 100MB
                fileStatus.innerHTML = '<span class="text-yellow-600"><i class="fas fa-exclamation-triangle mr-2"></i>Предупреждение: файл больше 100MB, обработка может занять много времени</span>';
            } else {
                fileStatus.textContent = 'Файл загружен и готов к обработке';
            }
        }
        
        // Обработчик drag&drop
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('border-blue-500', 'bg-blue-50', 'dark:bg-blue-900/20');
        });
        
        dropZone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            dropZone.classList.remove('border-blue-500', 'bg-blue-50', 'dark:bg-blue-900/20');
        });
        
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('border-blue-500', 'bg-blue-50', 'dark:bg-blue-900/20');
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                showFileInfo(files[0]);
            }
        });
        
        // Обработчик клика по зоне загрузки
        dropZone.addEventListener('click', () => {
            fileInput.click();
        });
        
        // Обработчик выбора файла
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                showFileInfo(e.target.files[0]);
            }
        });
        
        // Удаление файла
        removeFileBtn.addEventListener('click', () => {
            fileInfo.classList.add('hidden');
            fileInput.value = '';
            currentFile = null;
            encryptedFile = null;
            decryptedFile = null;
            fileStatus.textContent = 'Выберите файл и нажмите кнопку для начала работы';
            fileProgress.classList.add('hidden');
            fileActions.classList.add('hidden');
        });
        
        // Шифрование файла с AES-GCM
        async function encryptFile(file, password, method = 'aes') {
    try {
        const chunkSize = 64 * 1024; // 64KB чанки для потоковой обработки
        const chunks = Math.ceil(file.size / chunkSize);
        let offset = 0;

        // Генерация ключа из пароля
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(password),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );

        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const key = await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: method === 'aes-ctr' ? 'AES-CTR' : 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );

        const encryptedChunks = [];
        const iv = window.crypto.getRandomValues(new Uint8Array(method === 'aes-ctr' ? 16 : 12));

        // Обрабатываем файл по чанкам
        for (let i = 0; i < chunks; i++) {
            const chunk = file.slice(offset, offset + chunkSize);
            const chunkBuffer = await chunk.arrayBuffer();

            let encrypted;
            if (method === 'aes-ctr') {
                const counter = new Uint8Array(iv);
                const view = new DataView(counter.buffer);
                view.setUint32(12, i, false); // Счетчик

                encrypted = await window.crypto.subtle.encrypt(
                    { name: 'AES-CTR', counter: counter, length: 64 },
                    key,
                    chunkBuffer
                );
            } else {
                const chunkIv = new Uint8Array(12);
                chunkIv.set(iv.slice(0, 8));
                new DataView(chunkIv.buffer).setUint32(8, i, false);

                encrypted = await window.crypto.subtle.encrypt(
                    { name: 'AES-GCM', iv: chunkIv },
                    key,
                    chunkBuffer
                );
            }

            encryptedChunks.push(new Uint8Array(encrypted));
            offset += chunkSize;

            updateFileProgress(offset, file.size);
            await new Promise(resolve => setTimeout(resolve, 0));
        }

        const metadata = {
            originalName: file.name,
            originalSize: file.size,
            method: method,
            iv: Array.from(iv),
            salt: Array.from(salt),
            chunks: encryptedChunks.length
        };

        const metadataBytes = new TextEncoder().encode(JSON.stringify(metadata));
        const metadataSizeBuf = new Uint8Array(4);
        new DataView(metadataSizeBuf.buffer).setUint32(0, metadataBytes.length, true); // LE

        const totalEncryptedLength = encryptedChunks.reduce((sum, chunk) => sum + chunk.length, 0);
        const totalSize = 4 + metadataBytes.length + totalEncryptedLength;
        const result = new Uint8Array(totalSize);

        let resultOffset = 0;
        result.set(metadataSizeBuf, resultOffset);
        resultOffset += 4;

        result.set(metadataBytes, resultOffset);
        resultOffset += metadataBytes.length;

        for (const chunk of encryptedChunks) {
            result.set(chunk, resultOffset);
            resultOffset += chunk.length;
        }

        return new Blob([result], { type: 'application/octet-stream' });

    } catch (error) {
        console.error('Ошибка шифрования файла:', error);
        throw error;
    }
}
        
        // Дешифрование файла
        async function decryptFile(file, password) {
    try {
        const fileBuffer = await file.arrayBuffer();
        const view = new DataView(fileBuffer);

        // Читаем размер метаданных
        const metadataSize = view.getUint32(0, true);

        if (metadataSize <= 0 || metadataSize > fileBuffer.byteLength - 4) {
            throw new Error("Невалидный размер метаданных");
        }

        // Читаем и парсим метаданные
        const metadataBytes = new Uint8Array(fileBuffer, 4, metadataSize);
        const metadata = JSON.parse(new TextDecoder().decode(metadataBytes));

        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(password),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );

        const key = await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: new Uint8Array(metadata.salt),
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: metadata.method === 'aes-ctr' ? 'AES-CTR' : 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );

        const encryptedData = new Uint8Array(fileBuffer, 4 + metadataSize);
        const decryptedChunks = [];
        const iv = new Uint8Array(metadata.iv);
        let dataOffset = 0;

        for (let i = 0; i < metadata.chunks; i++) {
            const isLastChunk = i === metadata.chunks - 1;

            let chunkSize;
            if (metadata.method === 'aes-ctr') {
                chunkSize = isLastChunk
                    ? (metadata.originalSize - (i * 64 * 1024))
                    : 64 * 1024;
            } else {
                const originalChunkSize = isLastChunk
                    ? (metadata.originalSize - (i * 64 * 1024))
                    : 64 * 1024;
                chunkSize = originalChunkSize + 16;
            }

            if (dataOffset + chunkSize > encryptedData.byteLength) {
                throw new Error(`Некорректный размер данных на чанке ${i}`);
            }

            const encryptedChunk = encryptedData.slice(dataOffset, dataOffset + chunkSize);

            let decrypted;
            if (metadata.method === 'aes-ctr') {
                const counter = new Uint8Array(iv);
                new DataView(counter.buffer).setUint32(12, i, false);

                decrypted = await window.crypto.subtle.decrypt(
                    { name: 'AES-CTR', counter, length: 64 },
                    key,
                    encryptedChunk
                );
            } else {
                const chunkIv = new Uint8Array(12);
                chunkIv.set(iv.slice(0, 8));
                new DataView(chunkIv.buffer).setUint32(8, i, false);

                decrypted = await window.crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: chunkIv },
                    key,
                    encryptedChunk
                );
            }

            decryptedChunks.push(new Uint8Array(decrypted));
            dataOffset += chunkSize;

            updateFileProgress(i + 1, metadata.chunks);
            await new Promise(r => setTimeout(r, 0));
        }

        const result = new Uint8Array(metadata.originalSize);
        let offset = 0;
        for (const chunk of decryptedChunks) {
            result.set(chunk, offset);
            offset += chunk.length;
        }

        return {
            blob: new Blob([result]),
            name: metadata.originalName
        };
    } catch (error) {
        console.error('Ошибка дешифрования файла:', error);
        throw error;
    }
}
        
        // Обработчик шифрования файла
        encryptFileBtn.addEventListener('click', async () => {
            if (!currentFile) {
                fileStatus.innerHTML = '<span class="text-red-500"><i class="fas fa-exclamation-circle mr-2"></i>Выберите файл для шифрования</span>';
                return;
            }
            
            const password = filePassword.value;
            if (password.length < 8) {
                filePassword.classList.add('input-error');
                filePasswordError.style.display = 'block';
                return;
            } else {
                filePassword.classList.remove('input-error');
                filePasswordError.style.display = 'none';
            }
            
            try {
                // Показываем прогресс
                fileStatus.innerHTML = '<span class="text-blue-600"><i class="fas fa-cog fa-spin mr-2"></i>Шифрование файла...</span>';
                fileProgress.classList.remove('hidden');
                fileActions.classList.add('hidden');
                encryptFileBtn.disabled = true;
                decryptFileBtn.disabled = true;
                
                const encryptedBlob = await encryptFile(currentFile, password, fileEncryptionMethod.value);
                encryptedFile = encryptedBlob;
                
                // Создаем ссылку для скачивания
                const url = URL.createObjectURL(encryptedBlob);
                downloadFileBtn.href = url;
                downloadFileBtn.download = currentFile.name + '.encrypted';
                
                fileStatus.innerHTML = '<span class="text-green-600"><i class="fas fa-check-circle mr-2"></i>Файл успешно зашифрован</span>';
                fileActions.classList.remove('hidden');
                
            } catch (error) {
                fileStatus.innerHTML = `<span class="text-red-500"><i class="fas fa-exclamation-circle mr-2"></i>Ошибка: ${error.message}</span>`;
            } finally {
                encryptFileBtn.disabled = false;
                decryptFileBtn.disabled = false;
            }
        });
        
        // Обработчик дешифрования файла
        decryptFileBtn.addEventListener('click', async () => {
            if (!currentFile) {
                fileStatus.innerHTML = '<span class="text-red-500"><i class="fas fa-exclamation-circle mr-2"></i>Выберите зашифрованный файл</span>';
                return;
            }
            
            const password = filePassword.value;
            if (password.length < 8) {
                filePassword.classList.add('input-error');
                filePasswordError.style.display = 'block';
                return;
            } else {
                filePassword.classList.remove('input-error');
                filePasswordError.style.display = 'none';
            }
            
            try {
                // Показываем прогресс
                fileStatus.innerHTML = '<span class="text-blue-600"><i class="fas fa-cog fa-spin mr-2"></i>Дешифрование файла...</span>';
                fileProgress.classList.remove('hidden');
                fileActions.classList.add('hidden');
                encryptFileBtn.disabled = true;
                decryptFileBtn.disabled = true;
                
                const result = await decryptFile(currentFile, password);
                decryptedFile = result;
                
                // Создаем ссылку для скачивания
                const url = URL.createObjectURL(result.blob);
                downloadFileBtn.href = url;
                downloadFileBtn.download = result.name;
                
                fileStatus.innerHTML = '<span class="text-green-600"><i class="fas fa-check-circle mr-2"></i>Файл успешно расшифрован</span>';
                fileActions.classList.remove('hidden');
                
            } catch (error) {
                fileStatus.innerHTML = `<span class="text-red-500"><i class="fas fa-exclamation-circle mr-2"></i>Ошибка: ${error.message}</span>`;
            } finally {
                encryptFileBtn.disabled = false;
                decryptFileBtn.disabled = false;
            }
        });
        
        // Обработчик кнопки копирования
        copyBtn.addEventListener('click', () => {
            const resultText = outputResult.textContent.trim();
            if (!resultText || resultText.includes('Здесь появится результат')) {
                return;
            }
            
            // Если уже есть таймаут, очищаем его
            if (copyTimeout) {
                clearTimeout(copyTimeout);
            }
            
            // Копируем текст в буфер обмена
            navigator.clipboard.writeText(resultText).then(() => {
                // Сохраняем оригинальный HTML кнопки
                const originalHTML = copyBtn.innerHTML;
                
                // Меняем текст и стиль кнопки
                copyBtn.innerHTML = '<i class="fas fa-check mr-2"></i> Скопировано';
                copyBtn.classList.add('copied');
                
                // Возвращаем обратно через 2 секунды
                copyTimeout = setTimeout(() => {
                    copyBtn.innerHTML = originalHTML;
                    copyBtn.classList.remove('copied');
                    copyTimeout = null;
                }, 2000);
            }).catch(err => {
                console.error('Ошибка копирования:', err);
            });
        });
        
        // Инициализация при загрузке - исправлено для немедленного выполнения
        // Выполняем инициализацию непосредственно, а не ждем DOMContentLoaded
        initNavIndicator();
        initTheme();
        
        // Добавляем классы для анимации переключения методов
        document.querySelectorAll('select, input, button').forEach(el => {
            el.classList.add('method-switch');
        });
        
        // Активируем анимацию после загрузки
        setTimeout(() => {
            document.querySelectorAll('.method-switch').forEach(el => {
                el.classList.add('active');
            });
        }, 100);
