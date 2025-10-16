class SecurityUtils {
    static sanitizeHTML(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    static validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    static validateUsername(username) {
        const usernameRegex = /^[a-zA-Z0-9_-]{3,20}$/;
        return usernameRegex.test(username);
    }

    static validatePassword(password) {
        return password.length >= 8 &&
            /[A-Z]/.test(password) &&
            /[a-z]/.test(password) &&
            /[0-9]/.test(password);
    }

    static escapeRegex(str) {
        return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    static generateCSRFToken() {
        return crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2) + Date.now().toString(36);
    }
}

class SecureStorage {
    static setItem(key, value) {
        try {
            // Используем TextEncoder для безопасного кодирования
            const encoder = new TextEncoder();
            const data = encoder.encode(JSON.stringify(value));

            // Простое base64 кодирование (безопасная альтернатива escape/unescape)
            const base64 = btoa(String.fromCharCode(...data));
            localStorage.setItem(key, base64);
        } catch (error) {
            console.error('SecureStorage error:', error);
        }
    }

    static getItem(key) {
        try {
            const base64 = localStorage.getItem(key);
            if (!base64) return null;

            // Декодирование base64
            const binary = atob(base64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }

            // Используем TextDecoder для безопасного декодирования
            const decoder = new TextDecoder();
            return JSON.parse(decoder.decode(bytes));
        } catch (error) {
            console.error('SecureStorage error:', error);
            return null;
        }
    }

    static removeItem(key) {
        try {
            localStorage.removeItem(key);
        } catch (error) {
            console.error('SecureStorage error:', error);
        }
    }
}

class XSSProtection {
    static sanitizeUserInput(input) {
        if (typeof input !== 'string') return input;

        return input
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;')
            .replace(/\\/g, '&#x5C;')
            .replace(/`/g, '&#x60;');
    }

    static safeSetInnerHTML(element, content) {
        element.textContent = content;
    }

    static validateFileType(file, allowedTypes = ['image/jpeg', 'image/png', 'image/gif']) {
        return allowedTypes.includes(file.type);
    }

    static validateFileSize(file, maxSizeMB = 5) {
        return file.size <= maxSizeMB * 1024 * 1024;
    }
}

class RequestSecurity {
    constructor() {
        this.csrfToken = SecurityUtils.generateCSRFToken();
    }

    async makeSecureRequest(url, options = {}) {
        const defaultOptions = {
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': this.csrfToken,
                'X-Requested-With': 'XMLHttpRequest'
            }
        };

        const mergedOptions = {
            ...defaultOptions,
            ...options,
            headers: {
                ...defaultOptions.headers,
                ...options.headers
            }
        };

        try {
            const response = await fetch(url, mergedOptions);

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const contentType = response.headers.get('content-type');
            if (!contentType || !contentType.includes('application/json')) {
                throw new Error('Invalid response type');
            }

            return await response.json();
        } catch (error) {
            console.error('Request failed:', error);
            throw error;
        }
    }

    sanitizeRequestData(data) {
        const sanitized = {};
        for (const [key, value] of Object.entries(data)) {
            if (typeof value === 'string') {
                sanitized[key] = XSSProtection.sanitizeUserInput(value);
            } else {
                sanitized[key] = value;
            }
        }
        return sanitized;
    }
}

class SecureAuthSystem {
    constructor() {
        this.requestSecurity = new RequestSecurity();
        this.failedAttempts = 0;
        this.maxAttempts = 5;
        this.lockoutTime = 15 * 60 * 1000;
    }

    async register(email, username, password) {
        if (this.isLockedOut()) {
            throw new Error('Превышено количество попыток. Попробуйте позже.');
        }

        if (!SecurityUtils.validateEmail(email)) {
            this.recordFailedAttempt();
            throw new Error('Некорректный email');
        }

        if (!SecurityUtils.validateUsername(username)) {
            this.recordFailedAttempt();
            throw new Error('Имя пользователя должно содержать 3-20 символов (a-z, 0-9, _, -)');
        }

        if (!SecurityUtils.validatePassword(password)) {
            this.recordFailedAttempt();
            throw new Error('Пароль должен содержать минимум 8 символов, включая заглавные и строчные буквы и цифры');
        }

        try {
            const sanitizedData = this.requestSecurity.sanitizeRequestData({
                email: email.toLowerCase(),
                username,
                password
            });

            const response = await this.requestSecurity.makeSecureRequest('/api/register', {
                method: 'POST',
                body: JSON.stringify(sanitizedData)
            });

            if (response.success) {
                this.resetFailedAttempts();
            } else {
                this.recordFailedAttempt();
            }

            return response;
        } catch (error) {
            this.recordFailedAttempt();
            throw error;
        }
    }

    async login(identifier, password) {
        if (this.isLockedOut()) {
            throw new Error('Превышено количество попыток. Попробуйте позже.');
        }

        try {
            const sanitizedData = this.requestSecurity.sanitizeRequestData({
                identifier: identifier.toLowerCase(),
                password
            });

            const response = await this.requestSecurity.makeSecureRequest('/api/login', {
                method: 'POST',
                body: JSON.stringify(sanitizedData)
            });

            if (response.success) {
                this.resetFailedAttempts();
                this.storeUserSession(response.user);
            } else {
                this.recordFailedAttempt();
            }

            return response;
        } catch (error) {
            this.recordFailedAttempt();
            throw error;
        }
    }

    storeUserSession(user) {
        const sessionData = {
            user: user,
            timestamp: Date.now(),
            sessionId: SecurityUtils.generateCSRFToken()
        };
        SecureStorage.setItem('user_session', sessionData);
    }

    getCurrentUser() {
        const session = SecureStorage.getItem('user_session');
        if (!session || Date.now() - session.timestamp > 24 * 60 * 60 * 1000) {
            this.logout();
            return null;
        }
        return session.user;
    }

    logout() {
        SecureStorage.removeItem('user_session');
        SecureStorage.removeItem('weeklyActivity');
        SecureStorage.removeItem('totalOnlineTime');
    }

    recordFailedAttempt() {
        this.failedAttempts++;
        const lockoutUntil = Date.now() + this.lockoutTime;
        SecureStorage.setItem('auth_lockout', {
            attempts: this.failedAttempts,
            lockoutUntil: this.failedAttempts >= this.maxAttempts ? lockoutUntil : null
        });
    }

    resetFailedAttempts() {
        this.failedAttempts = 0;
        SecureStorage.removeItem('auth_lockout');
    }

    isLockedOut() {
        const lockout = SecureStorage.getItem('auth_lockout');
        if (!lockout) return false;

        this.failedAttempts = lockout.attempts;

        if (lockout.lockoutUntil && Date.now() < lockout.lockoutUntil) {
            return true;
        }

        if (lockout.lockoutUntil && Date.now() >= lockout.lockoutUntil) {
            this.resetFailedAttempts();
            return false;
        }

        return this.failedAttempts >= this.maxAttempts;
    }
}

class SecureFileUpload {
    static async validateAndUploadAvatar(file, userId) {
        if (!XSSProtection.validateFileType(file)) {
            throw new Error('Разрешены только файлы JPEG, PNG и GIF');
        }

        if (!XSSProtection.validateFileSize(file)) {
            throw new Error('Размер файла не должен превышать 5MB');
        }

        const fileName = XSSProtection.sanitizeUserInput(file.name);
        const fileExtension = fileName.split('.').pop().toLowerCase();

        if (!['jpg', 'jpeg', 'png', 'gif'].includes(fileExtension)) {
            throw new Error('Недопустимое расширение файла');
        }

        return new Promise((resolve, reject) => {
            const reader = new FileReader();

            reader.onload = async (e) => {
                try {
                    const base64Data = e.target.result.split(',')[1];

                    const response = await fetch('/api/upload_avatar', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRF-Token': SecurityUtils.generateCSRFToken()
                        },
                        body: JSON.stringify({
                            file_data: base64Data,
                            filename: `avatar_${userId}.${fileExtension}`,
                            user_id: userId
                        })
                    });

                    const result = await response.json();

                    if (result.success) {
                        resolve(result);
                    } else {
                        reject(new Error(result.message || 'Ошибка загрузки'));
                    }
                } catch (error) {
                    reject(error);
                }
            };

            reader.onerror = () => reject(new Error('Ошибка чтения файла'));
            reader.readAsDataURL(file);
        });
    }
}

document.addEventListener('DOMContentLoaded', function () {
    const secureAuth = new SecureAuthSystem();
    const requestSecurity = new RequestSecurity();

    let currentUser = null;
    let verificationData = null;
    let sessionStartTime = null;
    let totalOnlineTime = 0;
    let sessionTimer = null;
    let weeklyActivity = {};

    function initAuthSystem() {
        setupModalEvents();
        setupAuthForms();
        loadUserFromStorage();
        loadActivityData();
        setupCSP();
    }

    function setupCSP() {
        const meta = document.createElement('meta');
        meta.httpEquiv = 'Content-Security-Policy';
        meta.content = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self';";
        document.head.appendChild(meta);
    }

    function setupModalEvents() {
        const registerModal = document.getElementById('register-modal');
        const loginModal = document.getElementById('login-modal');
        const registerLink = document.getElementById('register-link');
        const loginLink = document.getElementById('login-link');
        const closeBtns = document.querySelectorAll('.close-modal');

        if (registerLink) {
            registerLink.addEventListener('click', function (e) {
                e.preventDefault();
                if (registerModal) {
                    registerModal.style.display = 'block';
                    showForm('register-form', registerModal);
                }
            });
        }

        if (loginLink) {
            loginLink.addEventListener('click', function (e) {
                e.preventDefault();
                if (loginModal) {
                    loginModal.style.display = 'block';
                    showForm('login-form', loginModal);
                }
            });
        }

        closeBtns.forEach(btn => {
            btn.addEventListener('click', function () {
                const modal = this.closest('.modal');
                if (modal) {
                    modal.style.display = 'none';
                    resetForms();
                }
            });
        });

        window.addEventListener('click', function (e) {
            if (e.target.classList.contains('modal')) {
                e.target.style.display = 'none';
                resetForms();
            }
        });
    }

    function setupAuthForms() {
        const registerForm = document.getElementById('register-form');
        const codeForm = document.getElementById('code-form');
        const loginForm = document.getElementById('login-form');

        if (registerForm) {
            registerForm.addEventListener('submit', function (e) {
                e.preventDefault();
                sendVerificationCode();
            });
        }

        if (codeForm) {
            codeForm.addEventListener('submit', function (e) {
                e.preventDefault();
                verifyCodeAndRegister();
            });
        }

        if (loginForm) {
            loginForm.addEventListener('submit', function (e) {
                e.preventDefault();
                loginUser();
            });
        }

        const passwordInput = document.getElementById('reg-password');
        if (passwordInput) {
            passwordInput.addEventListener('input', function () {
                updatePasswordStrength(this.value);
            });
        }

        const uploadBtn = document.querySelector('.upload-btn');
        if (uploadBtn) {
            uploadBtn.addEventListener('click', function () {
                document.getElementById('avatar-input').click();
            });
        }

        const avatarInput = document.getElementById('avatar-input');
        if (avatarInput) {
            avatarInput.addEventListener('change', function (e) {
                const file = e.target.files[0];
                if (file) {
                    uploadAvatar(file);
                }
            });
        }

        const profileLogoutBtn = document.getElementById('profile-logout-btn');
        if (profileLogoutBtn) {
            profileLogoutBtn.addEventListener('click', function (e) {
                e.preventDefault();
                logoutUser();
            });
        }
    }

    function showForm(formId, modal) {
        const forms = modal.querySelectorAll('.auth-form');
        forms.forEach(form => {
            form.classList.remove('active');
        });
        const targetForm = modal.querySelector(`#${formId}`);
        if (targetForm) {
            targetForm.classList.add('active');
        }
    }

    function resetForms() {
        const registerForm = document.getElementById('register-form');
        const codeForm = document.getElementById('code-form');
        const loginForm = document.getElementById('login-form');

        if (registerForm) registerForm.reset();
        if (codeForm) codeForm.reset();
        if (loginForm) loginForm.reset();

        const strengthBar = document.getElementById('strength-bar');
        if (strengthBar) strengthBar.style.width = '0%';

        verificationData = null;
    }

    function updatePasswordStrength(password) {
        const strengthBar = document.getElementById('strength-bar');
        if (!strengthBar) return;

        let strength = 0;
        if (password.length >= 6) strength += 25;
        if (password.length >= 8) strength += 25;
        if (/[A-Z]/.test(password)) strength += 25;
        if (/[0-9]/.test(password)) strength += 25;

        strengthBar.style.width = strength + '%';

        if (strength < 50) {
            strengthBar.style.background = '#ff4444';
        } else if (strength < 75) {
            strengthBar.style.background = '#ffa726';
        } else {
            strengthBar.style.background = '#00c853';
        }
    }

    async function sendVerificationCode() {
        const email = document.getElementById('reg-email')?.value;
        const username = document.getElementById('reg-username')?.value;
        const password = document.getElementById('reg-password')?.value;

        if (!email || !username || !password) {
            showNotification('Заполните все поля', 'error');
            return;
        }

        const submitBtn = document.getElementById('register-submit');
        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.innerHTML = 'Отправка...';
        }

        try {
            const sanitizedData = requestSecurity.sanitizeRequestData({ email, username });

            const response = await requestSecurity.makeSecureRequest('/api/send_verification', {
                method: 'POST',
                body: JSON.stringify(sanitizedData)
            });

            if (response.success) {
                verificationData = { email, username, password };
                const emailDisplay = document.getElementById('email-display');
                if (emailDisplay) {
                    XSSProtection.safeSetInnerHTML(emailDisplay, email);
                }

                showForm('code-form', document.getElementById('register-modal'));
                startTimer();
                showNotification('Код отправлен на вашу почту', 'success');
            } else {
                showNotification(response.message, 'error');
            }
        } catch (error) {
            showNotification('Ошибка сети', 'error');
        } finally {
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.innerHTML = 'Подтвердить';
            }
        }
    }

    function startTimer() {
        let timeLeft = 60;
        const timerElement = document.getElementById('countdown');
        const timerContainer = document.getElementById('timer');

        if (!timerElement || !timerContainer) return;

        const timer = setInterval(() => {
            timeLeft--;
            XSSProtection.safeSetInnerHTML(timerElement, timeLeft.toString());

            if (timeLeft <= 0) {
                clearInterval(timer);
                const resendLink = document.createElement('a');
                resendLink.href = '#';
                resendLink.style.color = '#8a2be2';
                resendLink.textContent = 'Отправить код повторно';
                resendLink.onclick = (e) => {
                    e.preventDefault();
                    resendCode();
                };
                timerContainer.innerHTML = '';
                timerContainer.appendChild(resendLink);
            }
        }, 1000);
    }

    async function resendCode() {
        if (verificationData) {
            await sendVerificationCode();
        }
    }

    async function verifyCodeAndRegister() {
        const codeInput = document.getElementById('verification-code');
        if (!codeInput) return;

        const code = codeInput.value;

        if (!code || code.length !== 6 || !/^\d+$/.test(code)) {
            showNotification('Введите 6-значный цифровой код', 'error');
            return;
        }

        if (!verificationData) {
            showNotification('Данные верификации не найдены', 'error');
            return;
        }

        const submitBtn = document.getElementById('verify-submit');
        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.innerHTML = 'Регистрация...';
        }

        try {
            const response = await secureAuth.register(
                verificationData.email,
                verificationData.username,
                verificationData.password
            );

            if (response.success) {
                showNotification('Регистрация успешна!', 'success');

                const modal = document.getElementById('register-modal');
                if (modal) modal.style.display = 'none';

                await loginUserDirect(verificationData.email, verificationData.password);
                resetForms();
            } else {
                showNotification(response.message, 'error');
            }
        } catch (error) {
            showNotification(error.message, 'error');
        } finally {
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.innerHTML = 'Подтвердить код';
            }
        }
    }

    async function loginUser() {
        const identifier = document.getElementById('login-identifier')?.value;
        const password = document.getElementById('login-password')?.value;

        if (!identifier || !password) {
            showNotification('Заполните все поля', 'error');
            return;
        }

        const submitBtn = document.getElementById('login-submit');
        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.innerHTML = 'Вход...';
        }

        try {
            const response = await secureAuth.login(identifier, password);

            if (response.success) {
                currentUser = response.user;
                updateUIAfterLogin();
                startSessionTimer();
                showNotification('Добро пожаловать, ' + currentUser.username + '!', 'success');

                const modal = document.getElementById('login-modal');
                if (modal) modal.style.display = 'none';

                resetForms();
            } else {
                showNotification(response.message, 'error');
            }
        } catch (error) {
            showNotification(error.message, 'error');
        } finally {
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.innerHTML = 'Войти';
            }
        }
    }

    async function loginUserDirect(email, password) {
        try {
            const response = await secureAuth.login(email, password);

            if (response.success) {
                currentUser = response.user;
                updateUIAfterLogin();
                startSessionTimer();
                showNotification('Добро пожаловать, ' + currentUser.username + '!', 'success');
            } else {
                showNotification(response.message, 'error');
            }
        } catch (error) {
            showNotification('Ошибка входа', 'error');
        }
    }

    function updateUIAfterLogin() {
        const registerLink = document.getElementById('register-link');
        const loginLink = document.getElementById('login-link');
        const profileLink = document.getElementById('profile-link');

        if (registerLink) registerLink.style.display = 'none';
        if (loginLink) loginLink.style.display = 'none';
        if (profileLink) profileLink.style.display = 'block';
    }

    function loadUserFromStorage() {
        currentUser = secureAuth.getCurrentUser();
        if (currentUser) {
            updateUIAfterLogin();
            startSessionTimer();
        }
    }

    function loadProfilePage() {
        if (!currentUser) return;

        XSSProtection.safeSetInnerHTML(document.getElementById('profile-username'), currentUser.username);
        XSSProtection.safeSetInnerHTML(document.getElementById('profile-email'), currentUser.email);
        XSSProtection.safeSetInnerHTML(document.getElementById('profile-date'), new Date(currentUser.created_at).toLocaleDateString('ru-RU'));
        XSSProtection.safeSetInnerHTML(document.getElementById('user-id'), currentUser.id.toString());

        const profileAvatar = document.getElementById('profile-avatar');
        profileAvatar.src = currentUser.avatar_url;

        updateActivityChart();
    }

    async function uploadAvatar(file) {
        if (!currentUser) return;

        try {
            const result = await SecureFileUpload.validateAndUploadAvatar(file, currentUser.id);

            if (result.success) {
                currentUser.avatar_url = result.avatar_url;
                secureAuth.storeUserSession(currentUser);

                document.getElementById('profile-avatar').src = result.avatar_url;
                showNotification('Аватар обновлен', 'success');
            } else {
                showNotification(result.message, 'error');
            }
        } catch (error) {
            showNotification(error.message, 'error');
        }
    }

    function loadActivityData() {
        const savedActivity = SecureStorage.getItem('weeklyActivity');
        if (savedActivity) {
            weeklyActivity = savedActivity;
        } else {
            const days = ['Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб', 'Вс'];
            days.forEach(day => {
                weeklyActivity[day] = 0;
            });
        }
    }

    function saveActivityData() {
        SecureStorage.setItem('weeklyActivity', weeklyActivity);
    }

    function updateActivityChart() {
        const days = ['Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб', 'Вс'];
        const chartBars = document.querySelectorAll('.chart-bar');

        days.forEach((day, index) => {
            if (chartBars[index]) {
                const hours = weeklyActivity[day] || 0;
                const percentage = Math.min((hours / 24) * 100, 100);
                const barSegment = chartBars[index].querySelector('.bar-segment');
                if (barSegment) {
                    barSegment.style.height = percentage + '%';
                }
            }
        });
    }

    function startSessionTimer() {
        sessionStartTime = new Date();

        const savedTime = SecureStorage.getItem('totalOnlineTime');
        totalOnlineTime = savedTime ? parseInt(savedTime) : 0;

        const today = new Date().toLocaleDateString('ru-RU');
        const dayOfWeek = getDayOfWeek(new Date());
        weeklyActivity[dayOfWeek] = (weeklyActivity[dayOfWeek] || 0);

        updateOnlineStats();

        sessionTimer = setInterval(updateSessionTime, 1000);
    }

    function getDayOfWeek(date) {
        const days = ['Вс', 'Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб'];
        return days[date.getDay()];
    }

    function updateSessionTime() {
        if (!sessionStartTime) return;

        const now = new Date();
        const sessionTime = Math.floor((now - sessionStartTime) / 1000);

        const hours = Math.floor(sessionTime / 3600);
        const minutes = Math.floor((sessionTime % 3600) / 60);
        const seconds = sessionTime % 60;

        XSSProtection.safeSetInnerHTML(document.getElementById('session-timer'),
            `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`);

        XSSProtection.safeSetInnerHTML(document.getElementById('current-session'),
            `${hours > 0 ? hours + 'ч ' : ''}${minutes}м`);

        totalOnlineTime++;
        SecureStorage.setItem('totalOnlineTime', totalOnlineTime.toString());

        const dayOfWeek = getDayOfWeek(now);
        weeklyActivity[dayOfWeek] = (weeklyActivity[dayOfWeek] || 0) + (1 / 3600);
        saveActivityData();

        updateOnlineStats();
        updateActivityChart();
    }

    function updateOnlineStats() {
        const totalHours = Math.floor(totalOnlineTime / 3600);
        const totalMinutes = Math.floor((totalOnlineTime % 3600) / 60);

        XSSProtection.safeSetInnerHTML(document.getElementById('total-online'), `${totalHours}ч`);
        XSSProtection.safeSetInnerHTML(document.getElementById('total-time'), `${totalHours}ч ${totalMinutes}м`);

        const today = new Date();
        const todayKey = getDayOfWeek(today);
        const todayHours = Math.floor(weeklyActivity[todayKey] || 0);
        const todayMinutes = Math.floor(((weeklyActivity[todayKey] || 0) % 1) * 60);
        XSSProtection.safeSetInnerHTML(document.getElementById('today-online'), `${todayHours}ч ${todayMinutes}м`);

        let weekTotal = 0;
        Object.values(weeklyActivity).forEach(hours => {
            weekTotal += hours;
        });
        const weekHours = Math.floor(weekTotal);
        const weekMinutes = Math.floor((weekTotal % 1) * 60);
        XSSProtection.safeSetInnerHTML(document.getElementById('week-online'), `${weekHours}ч ${weekMinutes}м`);

        const monthTotal = weekTotal * 4;
        const monthHours = Math.floor(monthTotal);
        const monthMinutes = Math.floor((monthTotal % 1) * 60);
        XSSProtection.safeSetInnerHTML(document.getElementById('month-online'), `${monthHours}ч ${monthMinutes}м`);

        if (sessionStartTime) {
            XSSProtection.safeSetInnerHTML(document.getElementById('session-start'),
                sessionStartTime.toLocaleTimeString('ru-RU'));
        }

        const avgSession = totalOnlineTime > 0 ? Math.floor(totalOnlineTime / 3600) / 10 : 0;
        XSSProtection.safeSetInnerHTML(document.getElementById('avg-session'), `${Math.floor(avgSession * 60)}м`);

        const recordSession = Math.max(...Object.values(weeklyActivity));
        const recordHours = Math.floor(recordSession);
        const recordMinutes = Math.floor((recordSession % 1) * 60);
        XSSProtection.safeSetInnerHTML(document.getElementById('record-session'), `${recordHours}ч ${recordMinutes}м`);
    }

    function logoutUser() {
        if (sessionTimer) {
            clearInterval(sessionTimer);
        }
        secureAuth.logout();
        currentUser = null;

        const registerLink = document.getElementById('register-link');
        const loginLink = document.getElementById('login-link');
        const profileLink = document.getElementById('profile-link');

        if (registerLink) registerLink.style.display = 'block';
        if (loginLink) loginLink.style.display = 'block';
        if (profileLink) profileLink.style.display = 'none';

        showNotification('До свидания!', 'info');
        setActivePage('main-subpage');
    }

    function showNotification(message, type = 'success') {
        const colors = {
            success: 'rgba(0, 200, 83, 0.9)',
            error: 'rgba(244, 67, 54, 0.9)',
            warning: 'rgba(255, 152, 0, 0.9)',
            info: 'rgba(33, 150, 243, 0.9)'
        };

        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: ${colors[type] || colors.success};
            color: white;
            padding: 15px 20px;
            border-radius: 10px;
            z-index: 10000;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            animation: slideInRight 0.3s ease;
            max-width: 400px;
            word-wrap: break-word;
        `;
        XSSProtection.safeSetInnerHTML(notification, message);
        document.body.appendChild(notification);

        setTimeout(() => {
            notification.style.animation = 'slideOutRight 0.3s ease';
            setTimeout(() => {
                notification.remove();
            }, 300);
        }, 4000);
    }

    const links = document.querySelectorAll('.nav-link');
    const contents = document.querySelectorAll('.content');

    function setActivePage(pageId) {
        contents.forEach(content => {
            content.classList.remove('active');
        });

        links.forEach(link => {
            link.classList.remove('active');
        });

        const activeContent = document.getElementById(pageId);
        if (activeContent) {
            activeContent.classList.add('active');
        }

        const activeLink = document.querySelector(`[data-page="${getPageName(pageId)}"]`);
        if (activeLink) {
            activeLink.classList.add('active');
        }

        if (pageId === 'profile-page' && currentUser) {
            loadProfilePage();
        }
    }

    function getPageName(pageId) {
        const pageMap = {
            'main-subpage': 'main',
            'developers-page': 'developers',
            'reviews-page': 'reviews',
            'tools-page': 'tools',
            'profile-page': 'profile',
            'services-page': 'services'
        };
        return pageMap[pageId] || pageId.replace('-page', '');
    }

    links.forEach(link => {
        link.addEventListener('click', function (e) {
            e.preventDefault();
            const targetPage = this.getAttribute('data-page');
            const pageId = targetPage === 'main' ? 'main-subpage' :
                targetPage === 'profile' ? 'profile-page' :
                    `${targetPage}-page`;
            setActivePage(pageId);
        });
    });

    setActivePage('main-subpage');
    initAuthSystem();
});

if (!document.querySelector('#notification-styles')) {
    const style = document.createElement('style');
    style.id = 'notification-styles';
    style.textContent = `
        @keyframes slideOutRight {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
        }
    `;
    document.head.appendChild(style);
}

window.resendCode = resendCode;
window.logoutUser = logoutUser;