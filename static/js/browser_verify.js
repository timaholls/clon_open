/**
 * Скрипт для проверки браузера и отправки данных для верификации
 */
document.addEventListener('DOMContentLoaded', function() {
    console.log("Проверка скрипта browser_verify.js...");

    // Проверяем, есть ли кука browser_verified
    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }

    // Упрощенная функция хеширования для демонстрации
    function simpleHash(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32bit integer
        }
        return hash.toString(16);
    }

    // Если нет куки browser_verified, отправляем запрос для верификации
    if (!getCookie('browser_verified')) {
        console.log("Выполняем проверку браузера...");

        // Собираем информацию о браузере
        const browserFeatures = {
            screenWidth: window.screen.width,
            screenHeight: window.screen.height,
            colorDepth: window.screen.colorDepth,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            language: navigator.language || navigator.userLanguage,
            cookiesEnabled: navigator.cookieEnabled,
            platform: navigator.platform,
            userAgent: navigator.userAgent,
            vendor: navigator.vendor,
            touchPoints: navigator.maxTouchPoints || 0,
            hardwareConcurrency: navigator.hardwareConcurrency || 0,
            deviceMemory: navigator.deviceMemory || 0,
            timezoneOffset: new Date().getTimezoneOffset()
        };

        // Создаем временный хеш на основе данных
        let challengeKey = btoa(JSON.stringify({
            timestamp: new Date().getTime(),
            random: Math.random().toString().substring(2)
        }));

        // Вычисляем простой хеш для отправки
        let featuresStr = JSON.stringify(browserFeatures);
        let challengeHash = simpleHash(challengeKey);
        let responseHash = simpleHash(challengeKey + '|' + featuresStr);

        console.log("Отправляем запрос на проверку браузера...");

        // Отправляем запрос
        fetch('/browser-verify/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                hash: responseHash,
                challenge_hash: challengeHash,
                redirect_url: window.location.pathname,
                browser_features: browserFeatures
            })
        })
        .then(response => {
            console.log("Получен ответ от сервера:", response.status);
            if (response.ok) {
                return response.json();
            }
            throw new Error('Проверка браузера не пройдена: ' + response.status);
        })
        .then(data => {
            console.log("Данные от сервера:", data);
            if (data.redirect) {
                // Перезагружаем страницу если нужно
                if (data.redirect !== window.location.pathname) {
                    window.location.href = data.redirect;
                }
            }
        })
        .catch(error => {
            console.error("Ошибка при проверке браузера:", error);
        });
    } else {
        console.log("Браузер уже проверен, куки найдена.");
    }
});
