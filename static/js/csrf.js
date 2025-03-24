/**
 * Функции для поддержки CSRF-токенов
 * Обновленная версия с валидацией токенов через Redis
 */

// Счетчик попыток обновления токенов
let tokenRefreshAttempts = 0;
const MAX_REFRESH_ATTEMPTS = 3;

// Функция для получения куки
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            // Ищем куки с нужным именем
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

/**
 * Функция для обновления CSRF-токена через API
 * @returns {Promise} Promise с результатом запроса
 */
function refreshCSRFToken() {
    tokenRefreshAttempts++;

    if (tokenRefreshAttempts > MAX_REFRESH_ATTEMPTS) {
        console.error('Max token refresh attempts reached. Please reload the page.');
        tokenRefreshAttempts = 0;
        // Предлагаем пользователю перезагрузить страницу
        if (confirm('Проблема с безопасностью сессии. Перезагрузить страницу?')) {
            window.location.reload();
        }
        return Promise.reject(new Error('Max refresh attempts reached'));
    }

    console.log(`Refreshing CSRF token (attempt ${tokenRefreshAttempts}/${MAX_REFRESH_ATTEMPTS})...`);

    return fetch('/api/csrf/refresh/', {
        method: 'GET',
        credentials: 'include',  // Включаем куки в запрос
        headers: {
            'Accept': 'application/json',
            'Cache-Control': 'no-cache, no-store'
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`Failed to refresh CSRF token: ${response.status} ${response.statusText}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('CSRF token refreshed successfully');
        tokenRefreshAttempts = 0; // Сбрасываем счетчик после успешного обновления

        // Получаем новый токен из кук
        const newToken = getCookie('csrftoken');
        if (!newToken) {
            console.warn('CSRF token not set in cookies after refresh');
            throw new Error('Token not set in cookies');
        }

        console.log(`New token received (${newToken.substring(0, 5)}...${newToken.substring(newToken.length - 5)})`);
        return newToken;
    })
    .catch(error => {
        console.error('Error refreshing CSRF token:', error);
        throw error;
    });
}

/**
 * Функция для выполнения fetch запросов с добавлением аутентификационных и CSRF токенов
 * @param {string} url - URL для запроса
 * @param {object} options - опции fetch запроса
 * @returns {Promise} результат fetch запроса
 */
function fetchWithAuth(url, options = {}) {
    // Получаем CSRF токен из куки
    const csrftoken = getCookie('csrftoken');

    // Если CSRF токен не найден, сначала обновляем его
    if (!csrftoken) {
        console.warn('CSRF token not found. Refreshing...');
        return refreshCSRFToken()
            .then(newToken => {
                return executeAuthenticatedFetch(url, options, newToken);
            });
    }

    // Если токен найден, сразу выполняем запрос
    return executeAuthenticatedFetch(url, options, csrftoken);
}

/**
 * Вспомогательная функция для выполнения аутентифицированного запроса
 * @param {string} url - URL для запроса
 * @param {object} options - опции fetch запроса
 * @param {string} csrftoken - CSRF токен
 * @returns {Promise} результат fetch запроса
 */
function executeAuthenticatedFetch(url, options, csrftoken) {
    // Создаем копию опций
    const secureOptions = { ...options };

    // Если заголовки не определены, создаем их
    if (!secureOptions.headers) {
        secureOptions.headers = {};
    }

    // Преобразуем заголовки в объект, если они переданы как Headers
    if (secureOptions.headers instanceof Headers) {
        const headersObj = {};
        for (const [key, value] of secureOptions.headers.entries()) {
            headersObj[key] = value;
        }
        secureOptions.headers = headersObj;
    }

    // Добавляем CSRF токен для всех запросов
    secureOptions.headers['X-CSRFToken'] = csrftoken;

    // Получаем аутентификационный токен из localStorage или sessionStorage
    const authToken = localStorage.getItem('authToken') || sessionStorage.getItem('authToken');

    // Если есть аутентификационный токен, добавляем его
    if (authToken) {
        secureOptions.headers['Authorization'] = `Token ${authToken}`;
    }

    // Включаем куки в запрос для всех запросов
    secureOptions.credentials = 'include';

    // Добавляем уникальный параметр для предотвращения кэширования
    const urlWithNoCaching = url.includes('?')
        ? `${url}&_=${Date.now()}`
        : `${url}?_=${Date.now()}`;

    // Выполняем fetch запрос с обработкой ошибок
    return fetch(urlWithNoCaching, secureOptions)
        .then(response => {
            // Если ответ содержит код 403 (Forbidden), возможно проблема с CSRF
            if (response.status === 403) {
                return response.json().catch(() => ({}))
                    .then(data => {
                        // Если ошибка связана с CSRF, пробуем обновить токен и повторить запрос
                        if (data.error && (
                            data.error.includes('CSRF') ||
                            data.error.includes('csrf') ||
                            data.error === 'Invalid CSRF token'
                        )) {
                            console.warn('CSRF token validation failed. Refreshing token...');
                            return refreshCSRFToken()
                                .then(newToken => {
                                    // Обновляем токен в опциях
                                    secureOptions.headers['X-CSRFToken'] = newToken;

                                    // Обновляем URL с новым временным штампом
                                    const refreshedUrl = url.includes('?')
                                        ? `${url}&_=${Date.now()}`
                                        : `${url}?_=${Date.now()}`;

                                    // Повторяем запрос с новым токеном
                                    console.log('Retrying request with new token...');
                                    return fetch(refreshedUrl, secureOptions);
                                });
                        }

                        // Если ошибка не связана с CSRF, возвращаем ответ как есть
                        console.error('Request failed with 403:', data.error || 'Unknown error');
                        return response;
                    });
            }

            return response;
        })
        .catch(error => {
            console.error('Fetch error:', error);
            throw error;
        });
}

// Установка CSRF-токена при загрузке страницы
document.addEventListener('DOMContentLoaded', () => {
    const csrftoken = getCookie('csrftoken');

    // Если CSRF токен не найден, запрашиваем новый
    if (!csrftoken) {
        console.log('No CSRF token found. Requesting initial token...');
        refreshCSRFToken()
            .then(token => {
                console.log('Initial CSRF token set up');
            })
            .catch(error => {
                console.error('Failed to set up initial CSRF token:', error);
            });
    } else {
        console.log(`CSRF token found: ${csrftoken.substring(0, 5)}...${csrftoken.substring(csrftoken.length - 5)}`);
    }

    // Настройка AJAX-запросов (для устаревшего кода, который использует XMLHttpRequest)
    const originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
        originalOpen.apply(this, arguments);

        // Для всех методов добавляем CSRF-токен
        const token = getCookie('csrftoken');
        if (token) {
            this.setRequestHeader('X-CSRFToken', token);
        }
    };
});
