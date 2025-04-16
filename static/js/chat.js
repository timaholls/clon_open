/**
 * ChatGPT Clone - Chat functionality
 * Uses the Auth module for authenticated API requests
 */

let creatingConversation = false;

// Global variable to store the selected file
let selectedFile = null;

// Function to handle file selection
function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        selectedFile = file;
        $('#attachment-preview').removeClass('hidden').addClass('flex');
        $('#attachment-name').text(file.name);

        // Enable send button even if there's no text
        $('#send-button').prop('disabled', false);
    }
}

// Function to remove selected file
function removeSelectedFile() {
    selectedFile = null;
    $('#attachment-preview').removeClass('flex').addClass('hidden');
    $('#attachment-name').text('');
    $('#file-input').val('');

    // Disable send button if there's no text
    if (!$('#message-input').val().trim()) {
        $('#send-button').prop('disabled', true);
    }
}

function scrollToBottom() {
    const messagesContainer = document.getElementById('messages-container');
    if (messagesContainer) {
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }
}

// Function to get CSRF token
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

// Function to refresh CSRF token
function refreshCsrfToken() {
    return new Promise((resolve, reject) => {
        // Add timestamp parameter to avoid caching
        const timestamp = new Date().getTime();
        fetch(`/api/csrf/refresh/?t=${timestamp}`, {
            method: 'GET',
            credentials: 'include'
        })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Failed to refresh CSRF token');
                }
                return response.json();
            })
            .then(data => {
                console.log('CSRF token refreshed successfully');
                // Return the new token from cookie
                resolve(getCookie('csrftoken'));
            })
            .catch(error => {
                console.error('Error refreshing CSRF token:', error);
                reject(error);
            });
    });
}

// Обновить функцию для отображения сообщений пользователя с поддержкой вложений
function getUserMessageHTML(content, senderName = 'Пользователь', attachment = null) {
    const firstLetter = senderName.charAt(0).toUpperCase();

    // Формируем HTML для вложенного файла, если он есть
    let attachmentHTML = '';
    if (attachment) {
        if (attachment.type === 'image') {
            attachmentHTML = `
                <div class="mt-2 max-w-lg">
                    <img src="${attachment.url}" alt="Прикрепленное изображение"
                         class="rounded-md max-h-[300px] border border-zinc-700" />
                </div>
            `;
        } else {
            attachmentHTML = `
                <div class="flex items-center p-2 mt-2 bg-zinc-800 rounded-md max-w-md border border-zinc-700">
                    <i class="ri-file-text-line text-zinc-400 mr-2 text-xl"></i>
                    <span class="text-zinc-300 truncate">${attachment.name}</span>
                    <a href="${attachment.url}" download
                       class="ml-auto text-zinc-400 hover:text-white" target="_blank">
                        <i class="ri-download-line"></i>
                    </a>
                </div>
            `;
        }
    }

    return `
        <div class="py-5 -mx-4 px-4">
            <div class="max-w-3xl mx-auto flex">
                <div class="flex-shrink-0 mr-4 mt-1">
                    <div class="w-7 h-7 rounded-full bg-zinc-700 flex items-center justify-center text-white">
                        ${firstLetter}
                    </div>
                </div>
                <div class="flex-1">
                    <div class="flex items-center mb-1">
                        <span class="text-white font-medium">${senderName}</span>
                    </div>
                    <div class="prose prose-invert max-w-none">
                        ${content ? `<div class="text-white whitespace-pre-wrap">${content}</div>` : ''}
                        ${attachmentHTML}
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Обновить функцию для отображения сообщений ассистента
function getAssistantMessageHTML(content, senderName = 'ChatGPT') {
    return `
        <div class="py-5 bg-zinc-800/40 -mx-4 px-4">
            <div class="max-w-3xl mx-auto flex">
                <div class="flex-shrink-0 mr-4 mt-1">
                    <div class="w-7 h-7 rounded-full bg-[#19c37d] flex items-center justify-center">
                        <svg width="24" height="24" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                            <path d="M22.2819 9.8211a5.9847 5.9847 0 0 0-.5157-4.9108 6.0462 6.0462 0 0 0-6.5098-2.9A6.0651 6.0651 0 0 0 4.9807 4.1818a5.9847 5.9847 0 0 0-3.9977 2.9 6.0462 6.0462 0 0 0 .7427 7.0966 5.98 5.98 0 0 0 .511 4.9107 6.051 6.051 0 0 0 6.5146 2.9001A5.9847 5.9847 0 0 0 13.2599 24a6.0557 6.0557 0 0 0 5.7718-4.2058 5.9894 5.9894 0 0 0 3.9977-2.9001 6.0557 6.0557 0 0 0-.7475-7.0729zm-9.022 12.6081a4.4755 4.4755 0 0 1-2.8764-1.0408l.1419-.0804 4.7783-2.7582a.7948.7948 0 0 0 .3927-.6813v-6.7369l2.02 1.1686a.071.071 0 0 1 .038.052v5.5826a4.504 4.504 0 0 1-4.4945 4.4944zm-9.6607-4.1254a4.4708 4.4708 0 0 1-.5346-3.0137l.142.0852 4.783 2.7582a.7712.7712 0 0 0 .7806 0l5.8428-3.3685v2.3324a.0804.0804 0 0 1-.0332.0615L9.74 19.9502a4.4992 4.4992 0 0 1-6.1408-1.6464zM2.3408 7.8956a4.485 4.485 0 0 1 2.3655-1.9728V11.6a.7664.7664 0 0 0 .3879.6765l5.8144 3.3543-2.0201 1.1685a.0757.0757 0 0 1-.071 0l-4.8303-2.7865A4.504 4.504 0 0 1 2.3408 7.872zm16.5963 3.8558L13.1038 8.364 15.1192 7.2a.0757.0757 0 0 1 .071 0l4.8303 2.7913a4.4944 4.4944 0 0 1-.6765 8.1042v-5.6772a.79.79 0 0 0-.407-.667zm2.0107-3.0231l-.142-.0852-4.7735-2.7818a.7759.7759 0 0 0-.7854 0L9.409 9.2297V6.8974a.0662.0662 0 0 1 .0284-.0615l4.8303-2.7866a4.4992 4.4992 0 0 1 6.6802 4.66zM8.3065 12.863l-2.02-1.1638a.0804.0804 0 0 1-.038-.0567V6.0742a4.4992 4.4992 0 0 1 7.3757-3.4537l-.142.0805L8.704 5.459a.7948.7948 0 0 0-.3927.6813zm1.0976-2.3654l2.602-1.4998 2.6069 1.4998v2.9994l-2.5974 1.5087-2.6067-1.4997z" fill="#FFF" />
                        </svg>
                    </div>
                </div>
                <div class="flex-1">
                    <div class="flex items-center mb-1">
                        <span class="text-white font-medium">${senderName}</span>
                    </div>
                    <div class="prose prose-invert max-w-none">
                        <div class="text-white whitespace-pre-wrap">${content}</div>
                    </div>

                    <div class="flex items-center mt-4 space-x-2 text-zinc-400">
                        <button class="copy-btn p-1 rounded-md hover:bg-zinc-700">
                            <i class="ri-file-copy-line text-sm"></i>
                        </button>
                        <button class="thumbs-up-btn p-1 rounded-md hover:bg-zinc-700">
                            <i class="ri-thumb-up-line text-sm"></i>
                        </button>
                        <button class="thumbs-down-btn p-1 rounded-md hover:bg-zinc-700">
                            <i class="ri-thumb-down-line text-sm"></i>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function getThinkingMessageHTML() {
    return `
        <div id="thinking" class="py-5 bg-zinc-800/40 -mx-4 px-4">
            <div class="max-w-3xl mx-auto flex">
                <div class="flex-shrink-0 mr-4 mt-1">
                    <div class="w-7 h-7 rounded-full bg-[#19c37d] flex items-center justify-center">
                        <svg width="24" height="24" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                            <path d="M22.2819 9.8211a5.9847 5.9847 0 0 0-.5157-4.9108 6.0462 6.0462 0 0 0-6.5098-2.9A6.0651 6.0651 0 0 0 4.9807 4.1818a5.9847 5.9847 0 0 0-3.9977 2.9 6.0462 6.0462 0 0 0 .7427 7.0966 5.98 5.98 0 0 0 .511 4.9107 6.051 6.051 0 0 0 6.5146 2.9001A5.9847 5.9847 0 0 0 13.2599 24a6.0557 6.0557 0 0 0 5.7718-4.2058 5.9894 5.9894 0 0 0 3.9977-2.9001 6.0557 6.0557 0 0 0-.7475-7.0729zm-9.022 12.6081a4.4755 4.4755 0 0 1-2.8764-1.0408l.1419-.0804 4.7783-2.7582a.7948.7948 0 0 0 .3927-.6813v-6.7369l2.02 1.1686a.071.071 0 0 1 .038.052v5.5826a4.504 4.504 0 0 1-4.4945 4.4944zm-9.6607-4.1254a4.4708 4.4708 0 0 1-.5346-3.0137l.142.0852 4.783 2.7582a.7712.7712 0 0 0 .7806 0l5.8428-3.3685v2.3324a.0804.0804 0 0 1-.0332.0615L9.74 19.9502a4.4992 4.4992 0 0 1-6.1408-1.6464zM2.3408 7.8956a4.485 4.485 0 0 1 2.3655-1.9728V11.6a.7664.7664 0 0 0 .3879.6765l5.8144 3.3543-2.0201 1.1685a.0757.0757 0 0 1-.071 0l-4.8303-2.7865A4.504 4.504 0 0 1 2.3408 7.872zm16.5963 3.8558L13.1038 8.364 15.1192 7.2a.0757.0757 0 0 1 .071 0l4.8303 2.7913a4.4944 4.4944 0 0 1-.6765 8.1042v-5.6772a.79.79 0 0 0-.407-.667zm2.0107-3.0231l-.142-.0852-4.7735-2.7818a.7759.7759 0 0 0-.7854 0L9.409 9.2297V6.8974a.0662.0662 0 0 1 .0284-.0615l4.8303-2.7866a4.4992 4.4992 0 0 1 6.6802 4.66zM8.3065 12.863l-2.02-1.1638a.0804.0804 0 0 1-.038-.0567V6.0742a4.4992 4.4992 0 0 1 7.3757-3.4537l-.142.0805L8.704 5.459a.7948.7948 0 0 0-.3927.6813zm1.0976-2.3654l2.602-1.4998 2.6069 1.4998v2.9994l-2.5974 1.5087-2.6067-1.4997z" fill="#FFF" />
                        </svg>
                    </div>
                </div>
                <div class="flex-1">
                    <div class="flex space-x-2 items-center">
                        <div class="h-2 w-2 bg-zinc-400 rounded-full animate-pulse"></div>
                        <div class="h-2 w-2 bg-zinc-400 rounded-full animate-pulse delay-150"></div>
                        <div class="h-2 w-2 bg-zinc-400 rounded-full animate-pulse delay-300"></div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function getConversationItemHTML(id, title) {
    return `
        <div class="sidebar-item" data-conversation-id="${id}">
            <i class="ri-chat-1-line text-zinc-400 mr-2"></i>
            <span class="truncate flex-1" title="${title}">${title}</span>
            <button class="delete-conversation ml-auto text-zinc-500 opacity-0 hover:opacity-100 hover:text-zinc-300 px-1">
                <i class="ri-delete-bin-line"></i>
            </button>
        </div>
    `;
}

// Main chat functionality
$(document).ready(function () {
    // Восстановление последнего активного чата
    const lastConversationId = sessionStorage.getItem('currentConversationId');

    if (lastConversationId) {
        console.log("Restoring last conversation:", lastConversationId);

        // Проверим, есть ли такой элемент в сайдбаре
        const conversationExists = $(`.sidebar-item[data-conversation-id="${lastConversationId}"]`).length > 0;

        if (conversationExists) {
            // Загрузить последний активный разговор
            reloadConversation(lastConversationId);
        } else {
            console.log("Last conversation not found in sidebar");
            // Если разговор не найден, показать пустое состояние
            $('#empty-state').show();
            $('#messages').hide();
            $('#input-container').hide();
        }
    } else {
        // Если нет сохраненного ID разговора
        console.log("No saved conversation ID");

        // Проверяем, есть ли текущий ID разговора в скрытом поле
        const currentId = $('#current-conversation-id').val();

        if (currentId) {
            console.log("Using current conversation ID from hidden field:", currentId);
            reloadConversation(currentId);
        } else {
            console.log("No current conversation ID, showing empty state");
            $('#empty-state').show();
            $('#messages').hide();
            $('#input-container').hide();
        }
    }

    if (lastConversationId) {
        console.log("Restoring last conversation:", lastConversationId);

        // Проверим, существует ли такой разговор в DOM
        const conversationExists = $(`.sidebar-item[data-conversation-id="${lastConversationId}"]`).length > 0;

        if (conversationExists) {
            // Загрузить последний активный разговор
            reloadConversation(lastConversationId);
        } else {
            console.log("Last conversation not found in DOM, loading default view");
            // Если разговор не найден, показать пустое состояние
            $('#empty-state').show();
            $('#messages').hide();
            $('#input-container').hide();
        }
    }
    // DOM elements
    const $sidebar = $('#sidebar');
    const $mobileHeader = $('#mobile-header');
    const $messagesContainer = $('#messages-container');
    const $emptyState = $('#empty-state');
    const $messages = $('#messages');
    const $inputContainer = $('#input-container');
    const $messageInput = $('#message-input');
    const $sendButton = $('#send-button');
    const $emptyInput = $('#empty-input');
    const $conversationsList = $('#conversations-list');
    const $currentConversationId = $('#current-conversation-id');
    const $logoutButton = $('#logout-button');
    const $fileInput = $('#file-input');
    const $removeAttachment = $('#remove-attachment');

    // Function to get current conversation ID
    function getCurrentConversationId() {
        return $currentConversationId.val() || null;
    }

    // Function to set current conversation ID
    function setCurrentConversationId(id) {
        $currentConversationId.val(id);
    }

    // Function to start a new chat
    function startNewChat() {
        $emptyState.hide();
        $messages.show().empty();
        $inputContainer.show();
        $messageInput.focus();
    }

    // Function to make authenticated fetch requests
    function fetchWithAuth(url, options = {}) {
        // Get CSRF token for non-GET requests
        if (options.method && options.method !== 'GET') {
            if (!options.headers) {
                options.headers = {};
            }
            const csrftoken = getCookie('csrftoken');
            if (csrftoken) {
                options.headers['X-CSRFToken'] = csrftoken;
            }
        }

        // Ensure credentials are included
        options.credentials = 'include';

        return fetch(url, options)
            .then(response => {
                // Handle unauthorized or forbidden responses
                if (response.status === 401) {
                    // Redirect to login on unauthorized (not authenticated)
                    window.location.href = '/login/';
                    throw new Error('Authentication failed');
                }
                // Do not automatically redirect on 403 (forbidden) errors
                // as they could be CSRF issues that can be handled differently
                return response;
            });
    }

    // Обновленная функция создания нового чата
    function createNewConversation() {
        console.log("Creating new conversation");

        // Очистить поле сообщений перед созданием нового чата
        $('#messages').empty();

        // Показать индикатор загрузки
        $('#messages').html('<div class="loading text-white text-center p-4">Создание нового чата...</div>');

        // Скрыть пустое состояние, показать сообщения и ввод
        $('#empty-state').hide();
        $('#messages').show();
        $('#input-container').show();

        // Отправить запрос на создание нового чата
        fetchWithAuth('/api/conversations/create/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrftoken')
            }
        })
            .then(response => {
                if (!response.ok) {
                    if (response.status === 403) {
                        console.error('CSRF or Forbidden error occurred during conversation creation');
                        // Получаем свежий CSRF токен и пробуем еще раз после небольшой задержки
                        const newCsrfToken = getCookie('csrftoken');
                        if (newCsrfToken) {
                            console.log('Обнаружен новый CSRF токен, используем его для повторного запроса');
                            setTimeout(() => {
                                // Не выполняем автоматический повторный запрос, чтобы избежать дублирования
                                $('#messages').html('<div class="error text-yellow-500 text-center p-4">Проблема с проверкой безопасности. Пожалуйста, попробуйте снова.</div>');
                            }, 500);
                        }
                        throw new Error('CSRF validation failed');
                    }
                    throw new Error(`HTTP error! Status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                console.log("New conversation created:", data);

                // Очистить поле сообщений
                $('#messages').empty();

                // Обновить ID текущего разговора
                $('#current-conversation-id').val(data.id);
                sessionStorage.setItem('currentConversationId', data.id);

                // Добавить новый чат в сайдбар
                $('#conversations-list').prepend(getConversationItemHTML(data.id, data.title));

                // Активировать новый чат в сайдбаре
                $('.sidebar-item').removeClass('active');
                $(`.sidebar-item[data-conversation-id="${data.id}"]`).addClass('active');

                // Фокус на поле ввода
                $('#message-input').focus();

                console.log("Switched to new conversation:", data.id);
            })
            .catch(error => {
                console.error("Error creating new conversation:", error);
                $('#messages').html('<div class="error text-red-500 text-center p-4">Ошибка создания чата</div>');
            });
    }

    // Новая функция загрузки чата
    function reloadConversation(conversationId) {
        console.log("Reloading conversation:", conversationId);

        if (!conversationId) {
            console.error("No conversation ID provided");
            return;
        }

        // Очистить активные классы и установить для текущего чата
        $('.sidebar-item').removeClass('active');
        $(`.sidebar-item[data-conversation-id="${conversationId}"]`).addClass('active');

        // Установить текущий ID
        $('#current-conversation-id').val(conversationId);
        sessionStorage.setItem('currentConversationId', conversationId);

        // Очистить предыдущие сообщения
        $('#messages').empty();

        // Показать индикатор загрузки
        $('#messages').html(`
        <div id="loading-indicator" class="flex items-center justify-center h-full p-4">
            <div class="text-white">Загрузка сообщений...</div>
        </div>
    `);

        // Скрыть пустое состояние, показать сообщения и ввод
        $('#empty-state').hide();
        $('#messages').show();
        $('#input-container').show();

        // Загрузить сообщения
        const timestamp = new Date().getTime();
        fetch(`/api/conversations/${conversationId}/messages/?t=${timestamp}`, {
            method: 'GET',
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            },
            credentials: 'include'
        })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                console.log("Messages loaded:", data);

                // Очистить сообщения и индикатор загрузки
                $('#messages').empty();

                // Добавить сообщения
                if (data.messages && data.messages.length > 0) {
                    data.messages.forEach(msg => {
                        if (msg.role === 'user') {
                            $('#messages').append(getUserMessageHTML(msg.content, msg.sender_name || 'Пользователь', msg.attachment));
                        } else {
                            $('#messages').append(getAssistantMessageHTML(msg.content, msg.sender_name || 'ChatGPT'));
                        }
                    });
                } else {
                    $('#messages').html('<div class="text-zinc-500 text-center p-4">В этом чате пока нет сообщений</div>');
                }

                // Прокрутить вниз
                scrollToBottom();
            })
            .catch(error => {
                console.error('Error loading conversation:', error);
                $('#messages').html(`
            <div class="flex items-center justify-center h-full p-4">
                <div class="text-red-500">Ошибка загрузки чата. Попробуйте еще раз.</div>
            </div>
        `);
            });
    }

    // Function to delete a conversation
    function deleteConversation(conversationId) {
        fetchWithAuth(`/api/conversations/${conversationId}/delete/`, {
            method: 'POST',
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        })
            .then(response => response.json())
            .then(data => {
                // Remove from sidebar
                $(`.sidebar-item[data-conversation-id="${conversationId}"]`).remove();

                // If current conversation was deleted, show empty state
                if (getCurrentConversationId() === conversationId) {
                    $messages.empty().hide();
                    $inputContainer.hide();
                    $emptyState.show();
                    setCurrentConversationId('');
                }
            })
            .catch(error => {
                console.error('Error deleting conversation:', error);
            });
    }

    // Обновленная функция отправки сообщений с поддержкой файлов
    function sendMessage(message, file = null) {
        // Если нет ни сообщения, ни файла, выходим
        if (!message && !file) return;

        // Получить текущий ID разговора
        let conversationId = $('#current-conversation-id').val();
        console.log("Sending message to conversation:", conversationId);

        // Если нет текущего разговора, создадим новый
        if (!conversationId) {
            console.log("No current conversation, creating new one first");

            // Очистить поле сообщений
            $('#messages').empty();

            // Добавить сообщение пользователя (будет отправлено после создания чата)
            const username = $('.user-info span').text().trim() || 'Пользователь';

            // Подготавливаем превью вложения, если есть
            let attachmentPreview = null;
            if (file) {
                const isImage = file.type.startsWith('image/');
                if (isImage && window.URL) {
                    attachmentPreview = {
                        url: window.URL.createObjectURL(file),
                        name: file.name,
                        type: 'image'
                    };
                } else {
                    attachmentPreview = {
                        url: '#',
                        name: file.name,
                        type: 'document'
                    };
                }
            }

            // Добавляем сообщение с вложением, если есть
            $('#messages').append(getUserMessageHTML(message, username, attachmentPreview));

            // Очистить поле ввода и удалить выбранный файл
            $('#message-input').val('').trigger('input');
            $('#message-input').css('height', 'auto');
            if (file) {
                removeSelectedFile();
            }

            // Прокрутить вниз
            scrollToBottom();

            // Добавить индикатор загрузки
            $('#messages').append(getThinkingMessageHTML());
            scrollToBottom();

            // Создать новый чат и затем отправить сообщение
            fetchWithAuth('/api/conversations/create/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCookie('csrftoken')
                }
            })
                .then(response => response.json())
                .then(data => {
                    console.log("New conversation created for message:", data);

                    // Установить ID нового разговора
                    conversationId = data.id;
                    $('#current-conversation-id').val(conversationId);
                    sessionStorage.setItem('currentConversationId', conversationId);

                    // Добавить в сайдбар
                    $('#conversations-list').prepend(getConversationItemHTML(data.id, data.title));

                    // Активировать в сайдбаре
                    $('.sidebar-item').removeClass('active');
                    $(`.sidebar-item[data-conversation-id="${data.id}"]`).addClass('active');

                    // Теперь отправляем сообщение с ID нового разговора
                    sendMessageToServer(message, data.id, file);
                })
                .catch(error => {
                    console.error("Error creating conversation for message:", error);
                    $('#thinking').remove();
                    $('#messages').append(getAssistantMessageHTML(
                        'Ошибка создания чата. Пожалуйста, попробуйте еще раз.',
                        'ChatGPT'
                    ));
                    scrollToBottom();
                });
        } else {
            // Если уже есть ID разговора, просто отправляем сообщение
            const username = $('.user-info span').text().trim() || 'Пользователь';

            // Подготавливаем превью вложения, если есть
            let attachmentPreview = null;
            if (file) {
                const isImage = file.type.startsWith('image/');
                if (isImage && window.URL) {
                    attachmentPreview = {
                        url: window.URL.createObjectURL(file),
                        name: file.name,
                        type: 'image'
                    };
                } else {
                    attachmentPreview = {
                        url: '#',
                        name: file.name,
                        type: 'document'
                    };
                }
            }

            // Добавляем сообщение пользователя с вложением, если есть
            $('#messages').append(getUserMessageHTML(message, username, attachmentPreview));

            // Очищаем поле ввода и удаляем выбранный файл
            $('#message-input').val('').trigger('input');
            $('#message-input').css('height', 'auto');
            if (file) {
                removeSelectedFile();
            }

            // Прокручиваем вниз
            scrollToBottom();

            // Добавляем индикатор "думающего" ассистента
            $('#messages').append(getThinkingMessageHTML());
            scrollToBottom();

            // Отправляем сообщение на сервер
            sendMessageToServer(message, conversationId, file);
        }
    }

    // Обновленная функция отправки сообщения на сервер с поддержкой файлов
    function sendMessageToServer(message, conversationId, file = null) {
        let requestData;
        let headers = {
            'X-CSRFToken': getCookie('csrftoken')
        };

        // Если есть файл, используем FormData для отправки multipart/form-data
        if (file) {
            requestData = new FormData();
            if (message) {
                requestData.append('message', message);
            }
            requestData.append('conversation_id', conversationId);
            requestData.append('attachment', file);

            // Не добавляем Content-Type, браузер сам установит правильный с границей (boundary)
        } else {
            // Если файла нет, используем JSON как обычно
            headers['Content-Type'] = 'application/json';
            requestData = JSON.stringify({
                message: message,
                conversation_id: conversationId
            });
        }

        fetchWithAuth('/api/send_message/', {
            method: 'POST',
            headers: headers,
            body: requestData
        })
            .then(response => {
                if (!response.ok) {
                    if (response.status === 403) {
                        console.error('CSRF or Forbidden error occurred');
                        // Пробуем обновить CSRF токен
                        return refreshCsrfToken()
                            .then(newToken => {
                                console.log('Retrieved new CSRF token, retrying message send...');
                                // Не отправляем повторно сообщение, чтобы избежать дублирования
                                $('#thinking').remove();
                                $('#messages').append(getAssistantMessageHTML(
                                    'Произошла ошибка проверки безопасности. Пожалуйста, попробуйте отправить сообщение еще раз.',
                                    'ChatGPT'
                                ));
                                scrollToBottom();
                                throw new Error('CSRF validation failed, token refreshed');
                            })
                            .catch(err => {
                                // Если и обновление токена не помогло
                                throw new Error('CSRF validation failed and token refresh failed');
                            });
                    }
                    throw new Error(`HTTP error! Status: ${response.status}`);
                }
                return response.json();
            })
            .then(response => {
                // Удаляем индикатор "думающего" ассистента
                $('#thinking').remove();

                // Добавляем ответ ассистента
                $('#messages').append(getAssistantMessageHTML(response.message, 'ChatGPT'));

                // Запомнить текущий заголовок до обновления
                let currentTitle = '';
                if (conversationId) {
                    currentTitle = $(`.sidebar-item[data-conversation-id="${conversationId}"] span.truncate`).text();
                }

                // Если заголовок изменился
                if (response.conversation_title && response.conversation_title !== currentTitle) {
                    // Обновляем текст и атрибут title
                    const $titleSpan = $(`.sidebar-item[data-conversation-id="${conversationId}"] span.truncate`);
                    $titleSpan.text(response.conversation_title);
                    $titleSpan.attr('title', response.conversation_title);

                    console.log(`Updated conversation title to: ${response.conversation_title}`);
                }

                // Прокрутить до конца
                scrollToBottom();

                // Логирование для отладки
                console.log("Received message:", message);
                console.log("Response:", response.message);
                console.log("Conversation ID:", response.conversation_id);
                console.log("Conversation Title:", response.conversation_title);
                if (response.attachment) {
                    console.log("Attachment:", response.attachment);
                }
            })
            .catch(error => {
                // Удаляем индикатор "думающего" ассистента
                $('#thinking').remove();

                // Показываем сообщение об ошибке
                $('#messages').append(getAssistantMessageHTML(
                    'Извините, произошла ошибка. Пожалуйста, попробуйте еще раз.',
                    'ChatGPT'
                ));

                // Прокрутить до конца
                scrollToBottom();

                console.error('Error:', error);
            });
    }

    // Обновленные обработчики событий для отправки сообщений
    document.addEventListener('DOMContentLoaded', function () {
        // Получаем элементы формы
        const messageInput = document.getElementById('message-input');
        const sendButton = document.getElementById('send-button');
        const emptyInput = document.getElementById('empty-input');

        // File input change handler
        $('#file-input').on('change', function(e) {
            handleFileSelect(e);
        });

        // Remove attachment button handler
        $('#remove-attachment').on('click', function() {
            removeSelectedFile();
        });

        // Handle file selection
        if ($fileInput) {
            $fileInput.addEventListener('change', handleFileSelect);
        }

        // Handle removing attachment
        if ($removeAttachment) {
            $removeAttachment.addEventListener('click', removeSelectedFile);
        }

        // Обработчик клика на кнопку отправки
        if (sendButton) {
            sendButton.addEventListener('click', function () {
                const message = messageInput ? messageInput.value.trim() : '';
                if (message || selectedFile) {
                    sendMessage(message, selectedFile);
                }
            });
        }

        // Обработчик нажатия Enter в поле ввода
        if (messageInput) {
            messageInput.addEventListener('keydown', function (e) {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    const message = this.value.trim();
                    if (message || selectedFile) {
                        sendMessage(message, selectedFile);
                    }
                }
            });

            // Адаптивная высота поля ввода
            messageInput.addEventListener('input', function () {
                this.style.height = 'auto';
                this.style.height = this.scrollHeight + 'px';

                // Активация/деактивация кнопки отправки
                if (sendButton) {
                    sendButton.disabled = !this.value.trim() && !selectedFile;
                }
            });
        }

        // Обработчик пустого поля ввода на главном экране
        if (emptyInput) {
            emptyInput.addEventListener('keydown', function (e) {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    const message = this.value.trim();
                    if (message) {
                        // Получить текущий ID чата
                        const conversationId = document.getElementById('current-conversation-id').value;

                        // Если нет текущего чата, создаем новый
                        if (!conversationId) {
                            createNewConversation().then(() => {
                                // После создания чата отправляем сообщение
                                setTimeout(() => sendMessage(message), 300);
                            });
                        } else {
                            // Иначе используем текущий чат
                            document.getElementById('empty-state').style.display = 'none';
                            document.getElementById('messages').style.display = 'block';
                            document.getElementById('input-container').style.display = 'block';

                            // Отправляем сообщение
                            sendMessage(message);
                        }

                        // Очищаем поле ввода
                        this.value = '';
                    }
                }
            });
        }
    });

    // Функция для проверки ширины экрана (мобильный или десктоп)
    function isMobile() {
        return window.innerWidth < 768;
    }

    // Обновляем обработчик переключения сайдбара
    $('#toggle-sidebar').on('click', function () {
        const $sidebar = $('#sidebar');
        const $chatArea = $('#chat-area');
        const $mobileHeader = $('#mobile-header');

        $sidebar.toggleClass('hidden');

        // Разное поведение для мобильных и десктопных устройств
        if (isMobile()) {
            // Для мобильных: скрываем полностью и показываем кнопку открытия
            if ($sidebar.hasClass('hidden')) {
                $mobileHeader.removeClass('hidden').addClass('flex');
            } else {
                $mobileHeader.removeClass('flex').addClass('hidden');
            }
        } else {
            // Для десктопа: можем сужать сайдбар или использовать другие стили
            // Но НЕ показываем мобильный заголовок
            $mobileHeader.removeClass('flex').addClass('hidden');
            $chatArea.toggleClass('expanded');
        }
    });

    // И обратный обработчик для кнопки в мобильном заголовке
    $('#open-sidebar').on('click', function () {
        const $sidebar = $('#sidebar');
        const $chatArea = $('#chat-area');
        const $mobileHeader = $('#mobile-header');

        // Показываем сайдбар
        $sidebar.removeClass('hidden');

        // Скрываем мобильный заголовок
        $mobileHeader.removeClass('flex').addClass('hidden');

        // Убираем класс для расширения области чата
        $chatArea.removeClass('sidebar-hidden');
    });

    // Handle new chat button click
    $('#new-chat').on('click', function () {
        // Очистить текущий чат перед созданием нового
        $('#messages').empty();
        $('#current-conversation-id').val('');

        // Убрать активные классы в сайдбаре
        $('.sidebar-item').removeClass('active');

        // Создать новый чат
        createNewConversation();
    });

    // Handle sidebar item click (to load conversation)
    $(document).on('click', '.sidebar-item', function (e) {
        // Ignore clicks on delete button
        if ($(e.target).closest('.delete-conversation').length) {
            return;
        }
        const conversationId = $(this).data('conversation-id');
        if (conversationId) {
            reloadConversation(conversationId);
        }
    });

    // Handle delete conversation button click
    $(document).on('click', '.delete-conversation', function (e) {
        e.stopPropagation();
        const conversationId = $(this).closest('.sidebar-item').data('conversation-id');

        if (confirm('Вы действительно хотите удалить этот чат?')) {
            deleteConversation(conversationId);
        }
    });

    // Handle empty input in hero section
    $emptyInput.on('keydown', function (e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            const message = $(this).val().trim();
            if (message) {
                // If there's no current conversation, create one
                if (!getCurrentConversationId()) {
                    createNewConversation();
                } else {
                    startNewChat();
                }

                // Send the message once the conversation is ready
                setTimeout(function () {
                    sendMessage(message);
                }, 100);

                $(this).val('');
            }
        }
    });

    // Enable/disable send button based on input
    $messageInput.on('input', function () {
        $sendButton.prop('disabled', !$messageInput.val().trim() && !selectedFile);
    });

    // Adjust textarea height as user types
    $messageInput.on('input', function () {
        this.style.height = 'auto';
        this.style.height = (this.scrollHeight) + 'px';
    });

    // Handle message submission via button
    $sendButton.on('click', function () {
        const message = $messageInput.val().trim();
        if (message || selectedFile) {
            sendMessage(message, selectedFile);
        }
    });

    // Handle message submission via Enter key
    $messageInput.on('keydown', function (e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            const message = $(this).val().trim();
            if (message || selectedFile) {
                sendMessage(message, selectedFile);
            }
        }
    });

    // Handle copy button clicks
    $(document).on('click', '.copy-btn', function () {
        const messageText = $(this).closest('.flex-1').find('.whitespace-pre-wrap').text();

        // Create a temporary textarea to copy the text
        const $temp = $('<textarea>');
        $('body').append($temp);
        $temp.val(messageText).select();
        document.execCommand('copy');
        $temp.remove();

        // Visual feedback
        const $icon = $(this).find('i');
        $icon.removeClass('ri-file-copy-line').addClass('ri-check-line');
        setTimeout(function () {
            $icon.removeClass('ri-check-line').addClass('ri-file-copy-line');
        }, 2000);
    });

    // Handle thumbs up/down clicks
    $(document).on('click', '.thumbs-up-btn, .thumbs-down-btn', function () {
        const $icon = $(this).find('i');

        if ($(this).hasClass('thumbs-up-btn')) {
            $icon.closest('.thumbs-up-btn').addClass('text-green-400');
            $icon.closest('.thumbs-up-btn').siblings('.thumbs-down-btn').removeClass('text-red-400');
        } else {
            $icon.closest('.thumbs-down-btn').addClass('text-red-400');
            $icon.closest('.thumbs-down-btn').siblings('.thumbs-up-btn').removeClass('text-green-400');
        }
    });

    // Handle logout button
    if ($logoutButton.length) {
        $logoutButton.on('click', function (e) {
            e.preventDefault();

            // Send logout request with CSRF token
            fetch('/logout/', {
                method: 'POST',
                headers: {
                    'X-CSRFToken': getCookie('csrftoken')
                },
                credentials: 'include'
            })
                .then(() => {
                    // Redirect to login page
                    window.location.href = '/login/';
                })
                .catch(err => {
                    console.error('Logout error:', err);
                    // Redirect anyway in case of error
                    window.location.href = '/login/';
                });
        });
    }
});

// Скроллинг при загрузке страницы
$(document).ready(function () {
    scrollToBottom();

    // Также прокручивай вниз при изменении размера окна
    $(window).on('resize', function () {
        scrollToBottom();
    });

    // Отлавливай события мутации DOM для автоматической прокрутки при добавлении новых сообщений
    if (typeof MutationObserver !== 'undefined') {
        const messagesElement = document.getElementById('messages');
        if (messagesElement) {
            const observer = new MutationObserver(function (mutations) {
                scrollToBottom();
            });

            observer.observe(messagesElement, {
                childList: true,  // наблюдать за добавлением/удалением дочерних элементов
                subtree: true     // наблюдать за всем поддеревом
            });
        }
    }
});

// Вызов scrollToBottom при загрузке страницы
$(document).ready(function () {
    scrollToBottom();
});
