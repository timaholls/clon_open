/**
 * Файл для обработки действий аутентификации и CAPTCHA
 */

// Функция для обновления CAPTCHA
window.refreshCaptcha = function() {
    console.log("Refreshing CAPTCHA...");

    // Добавляем временную метку для предотвращения кэширования
    var timestamp = new Date().getTime();

    // Получаем CSRF-токен из cookie
    var csrftoken = getCookie('csrftoken');

    fetch('refresh-captcha/' + timestamp, {
        method: 'GET',
        headers: {
            'X-CSRFToken': csrftoken,
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        },
        cache: 'no-cache',  // Предотвращаем кэширование
        credentials: 'same-origin'
    })
    .then(function(response) {
        if (!response.ok) {
            throw new Error('Network response was not ok: ' + response.status);
        }
        console.log(response)
        return response.json();
    })
    .then(function(data) {
        console.log("CAPTCHA response received:", data.success);

        if (data.success) {
            console.log(data)
            // Получаем изображение и обновляем его
            var captchaImg = document.getElementById('captcha-image');
            if (captchaImg) {
                captchaImg.src = 'data:image/png;base64,' + data.captcha_image;
                console.log("CAPTCHA image updated");

                // Очищаем поле ввода
                var captchaInput = document.getElementById('captcha');
                if (captchaInput) {
                    captchaInput.value = '';
                    captchaInput.focus();
                }
            } else {
                console.error("Captcha image element not found");
            }
        } else {
            console.error("Failed to refresh CAPTCHA:", data.error);
        }
    })
    .catch(function(error) {
        console.error("Error during CAPTCHA refresh:", error);
    });

    // Предотвращаем отправку формы
    return false;
};

// Функция для получения CSRF-токена из cookie
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

// Проверка совпадения паролей (для формы регистрации)
document.addEventListener('DOMContentLoaded', function() {
    var passwordField = document.getElementById('password');
    var confirmPasswordField = document.getElementById('password_confirm');

    if (passwordField && confirmPasswordField) {
        function checkPasswords() {
            if (passwordField.value && confirmPasswordField.value) {
                if (passwordField.value !== confirmPasswordField.value) {
                    confirmPasswordField.setCustomValidity('Passwords do not match');
                    confirmPasswordField.style.borderColor = '#EF4444'; // red
                } else {
                    confirmPasswordField.setCustomValidity('');
                    confirmPasswordField.style.borderColor = '#10B981'; // green
                }
            } else {
                confirmPasswordField.setCustomValidity('');
                confirmPasswordField.style.borderColor = '';
            }
        }

        passwordField.addEventListener('input', checkPasswords);
        confirmPasswordField.addEventListener('input', checkPasswords);

        // Проверка сложности пароля
        passwordField.addEventListener('input', function() {
            const password = this.value;
            // Регулярное выражение для проверки сложности пароля
            const isStrong = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/.test(password);

            if (isStrong) {
                this.style.borderColor = '#10B981'; // green
            } else {
                this.style.borderColor = password.length > 0 ? '#EF4444' : ''; // red or default
            }
        });
    }

    // Настраиваем кнопки обновления CAPTCHA
    var refreshButtons = document.querySelectorAll('.refresh-captcha');
    refreshButtons.forEach(function(button) {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            return refreshCaptcha();
        });
    });

    // Предотвращение многократной отправки формы
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', function() {
            const submitButton = this.querySelector('button[type="submit"]');
            if (submitButton) {
                submitButton.disabled = true;
                submitButton.textContent = 'Signing in...';
            }
        });
    }

    const signupForm = document.getElementById('signup-form');
    if (signupForm) {
        signupForm.addEventListener('submit', function() {
            const submitButton = this.querySelector('button[type="submit"]');
            if (submitButton) {
                submitButton.disabled = true;
                submitButton.textContent = 'Signing up...';
            }
        });
    }
});
