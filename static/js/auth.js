/**
 * Файл для обработки действий аутентификации и CAPTCHA
 */
// Проверка совпадения паролей (для формы регистрации)
document.addEventListener('DOMContentLoaded', function () {
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
        passwordField.addEventListener('input', function () {
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
    refreshButtons.forEach(function (button) {
        button.addEventListener('click', function (e) {
            e.preventDefault();
            return refreshCaptcha();
        });
    });

    // Предотвращение многократной отправки формы
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', function () {
            const submitButton = this.querySelector('button[type="submit"]');
            if (submitButton) {
                submitButton.disabled = true;
                submitButton.textContent = 'Signing in...';
            }
        });
    }

    const signupForm = document.getElementById('signup-form');
    if (signupForm) {
        signupForm.addEventListener('submit', function () {
            const submitButton = this.querySelector('button[type="submit"]');
            if (submitButton) {
                submitButton.disabled = true;
                submitButton.textContent = 'Signing up...';
            }
        });
    }
});
