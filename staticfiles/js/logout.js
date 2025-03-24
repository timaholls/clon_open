/**
 * JavaScript для обработки выхода из системы
 */

document.addEventListener('DOMContentLoaded', function() {
    // Функция для выхода через JavaScript
    window.performLogout = function() {
        console.log('Performing logout via AJAX...');

        // Получаем CSRF-токен
        const csrftoken = getCookie('csrftoken');
        console.log('CSRF Token:', csrftoken);

        // Выполняем запрос на сервер
        fetch('logout/', {
            method: 'POST',
            headers: {
                'X-CSRFToken': csrftoken,
                'Content-Type': 'application/json'
            },
            credentials: 'same-origin'
        })
        .then(function(response) {
            console.log('Logout response status:', response.status);
            if (response.ok) {
                // Перенаправляем на страницу входа
                window.location.href = '/login/';
            } else {
                console.error('Logout failed:', response.statusText);
                // Альтернативный метод выхода
                window.location.href = '/logout/';
            }
        })
        .catch(function(error) {
            console.error('Error during logout:', error);
            // Альтернативный метод выхода
            window.location.href = '/logout/';
        });

        return false; // Предотвращаем стандартное поведение ссылки
    };

    // Получение значения cookie
    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                // Ищем куки по имени
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }

    // Находим все кнопки для выхода и добавляем обработчик
    const logoutButtons = document.querySelectorAll('.logout-button, a[href="/logout/"]');
    logoutButtons.forEach(function(button) {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            return performLogout();
        });
    });
});
