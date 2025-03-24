/**
 * Функции для поддержки CSRF-токенов
 */

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

// Установка CSRF-токена для всех AJAX-запросов
function setupCSRF() {
    const csrftoken = getCookie('csrftoken');

    // Добавляем CSRF-токен ко всем AJAX-запросам
    document.addEventListener('DOMContentLoaded', () => {
        // Добавляем CSRF-токен к форме выхода
        const logoutForm = document.getElementById('logout-form');
        if (logoutForm) {
            logoutForm.addEventListener('submit', (e) => {
                console.log('Submitting logout form with CSRF token...');
            });
        }

        // Настраиваем AJAX-запросы
        const xhr = new XMLHttpRequest();
        xhr.open = function(method, url) {
            const open = XMLHttpRequest.prototype.open;
            open.apply(this, arguments);

            if (method.toLowerCase() !== 'get') {
                this.setRequestHeader('X-CSRFToken', csrftoken);
            }
        };

        // Для fetch API
        const originalFetch = window.fetch;
<<<<<<< HEAD
=======
        console.log("csrftokennnnnnnn", csrftoken)
>>>>>>> 9f1077d (Первый чистый коммит с .gitignore)
        window.fetch = function(url, options = {}) {
            // Если это не GET запрос, добавляем CSRF-токен
            if (options.method && options.method.toLowerCase() !== 'get') {
                if (!options.headers) {
                    options.headers = {};
                }

                // Преобразуем заголовки в объект, если они переданы как Headers
                if (options.headers instanceof Headers) {
                    const headersObj = {};
                    for (const [key, value] of options.headers.entries()) {
                        headersObj[key] = value;
                    }
                    options.headers = headersObj;
                }

                // Добавляем CSRF-токен
                options.headers['X-CSRFToken'] = csrftoken;
            }

            return originalFetch(url, options);
        };
    });
}

// Вызываем функцию настройки CSRF-токенов
setupCSRF();
