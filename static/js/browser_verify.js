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

    // Если нет куки browser_verified, отправляем запрос для верификации
    if (!getCookie('browser_verified')) {
        console.log("Выполняем проверку браузера...");

        // Устанавливаем куку browser_verified
        document.cookie = "browser_verified=true; path=/; max-age=86400"; // Кука на 24 часа

        // Перезагружаем страницу
        window.location.reload();
    } else {
        console.log("Браузер уже проверен, куки найдена.");
    }
});