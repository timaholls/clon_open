/**
 * ChatGPT Clone - Chat functionality
 * Uses the Auth module for authenticated API requests
 */

// Chat state
let creatingConversation = false;
let selectedFile = null;
let currentAssistantId = null;

// Function to handle file selection from input
function handleFileSelect(event) {
    const file = event.target.files[0];
    if (!file) return;
    selectedFile = file;
    $('#attachment-preview').removeClass('hidden').addClass('flex');
    $('#attachment-name').text(file.name);
    $('#send-button').prop('disabled', false);
    if (file.type.startsWith('image/')) {
        showImagePreview(file);
    }
}

// Function to show image preview
function showImagePreview(file) {
    if (!file || !file.type.startsWith('image/')) return;
    const reader = new FileReader();
    reader.onload = e => {
        const imagePreview = document.getElementById('image-preview');
        const imagePreviewWrapper = document.getElementById('image-preview-wrapper');
        if (imagePreview && imagePreviewWrapper) {
            imagePreview.src = e.target.result;
            imagePreviewWrapper.style.display = 'block';
            imagePreviewWrapper.classList.remove('hidden');
        }
    };
    reader.readAsDataURL(file);
}

// Function to close image preview
function closeImagePreview() {
    const imagePreviewWrapper = document.getElementById('image-preview-wrapper');
    const imagePreview = document.getElementById('image-preview');
    if (imagePreviewWrapper && imagePreview) {
        imagePreviewWrapper.style.display = 'none';
        imagePreviewWrapper.classList.add('hidden');
        imagePreview.src = '';
    }
}

// Function to handle clipboard paste
function handleClipboardPaste(event) {
    const items = (event.clipboardData || event.originalEvent.clipboardData).items;
    for (let i = 0; i < items.length; i++) {
        const item = items[i];
        if (item.type.indexOf('image') !== -1) {
            event.preventDefault();
            const blob = item.getAsFile();
            const timestamp = Date.now();
            selectedFile = new File([blob], `clipboard_image_${timestamp}.png`, { type: blob.type });
            $('#attachment-preview').removeClass('hidden').addClass('flex');
            $('#attachment-name').text('Изображение из буфера обмена');
            $('#send-button').prop('disabled', false);
            showImagePreview(selectedFile);
            return;
        }
        if (item.type.indexOf('application/') !== -1) {
            event.preventDefault();
            const blob = item.getAsFile();
            if (blob) {
                const timestamp = Date.now();
                const extension = blob.type.split('/')[1] || 'file';
                selectedFile = new File([blob], `clipboard_file_${timestamp}.${extension}`, { type: blob.type });
                $('#attachment-preview').removeClass('hidden').addClass('flex');
                $('#attachment-name').text('Документ из буфера обмена');
                $('#send-button').prop('disabled', false);
                return;
            }
        }
    }
}

// Function to manually trigger clipboard paste
function triggerClipboardPaste() {
    navigator.clipboard.read()
        .then(clipboardItems => {
            for (const clipboardItem of clipboardItems) {
                for (const type of clipboardItem.types) {
                    if (type.startsWith('image/')) {
                        clipboardItem.getType(type)
                            .then(blob => {
                                const timestamp = new Date().getTime();
                                selectedFile = new File([blob], `clipboard_image_${timestamp}.png`, { type: blob.type });

                                // Update UI
                                $('#attachment-preview').removeClass('hidden').addClass('flex');
                                $('#attachment-name').text('Изображение из буфера обмена');

                                // Enable send button
                                $('#send-button').prop('disabled', false);

                                // Show image preview
                                showImagePreview(selectedFile);

                                console.log('Image pasted from clipboard using button');
                            });
                        return;
                    } else if (type.startsWith('application/')) {
                        clipboardItem.getType(type)
                            .then(blob => {
                                const timestamp = new Date().getTime();
                                const extension = blob.type.split('/')[1] || 'file';
                                selectedFile = new File([blob], `clipboard_file_${timestamp}.${extension}`, { type: blob.type });

                                // Update UI
                                $('#attachment-preview').removeClass('hidden').addClass('flex');
                                $('#attachment-name').text('Документ из буфера обмена');

                                // Enable send button
                                $('#send-button').prop('disabled', false);

                                console.log('File pasted from clipboard using button');
                            });
                        return;
                    }
                }
            }
        })
        .catch(err => {
            console.error('Failed to read clipboard contents: ', err);
            alert('Не удалось получить доступ к буферу обмена. Убедитесь, что вы дали разрешение на доступ к буферу обмена.');
        });
}

// Function to remove selected file
function removeSelectedFile() {
    selectedFile = null;
    $('#attachment-preview').removeClass('flex').addClass('hidden');
    $('#attachment-name').text('');
    $('#file-input').val('');
    closeImagePreview();
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

// Function to send message to GPT Assistant
function sendMessageToAssistant(message, conversationId = null) {
    // Disable send button during API call
    $('#send-button').prop('disabled', true);

    // If there's an active assistant, use its ID
    const assistantId = currentAssistantId;

    // Create form data object for the request
    const data = {
        message: message,
        conversation_id: conversationId,
        assistant_id: assistantId
    };

    // Add attachment if there is one
    if (selectedFile) {
        data.has_attachment = true;

        const reader = new FileReader();
        reader.onload = function(e) {
            data.attachment = {
                name: selectedFile.name,
                type: selectedFile.type,
                data: e.target.result
            };

            // Now send the message with the attachment
            sendMessageWithData(data);
        };
        reader.readAsDataURL(selectedFile);
    } else {
        // Send message without attachment
        sendMessageWithData(data);
    }
}

// Helper function to actually send the API request
function sendMessageWithData(data) {
    // Add the user message to the UI first
    addMessageToUI('user', data.message, selectedFile);

    // Reset file selection
    resetAttachment();

    // Show typing indicator while waiting for response
    showTypingIndicator();

    // Use the new API endpoint for GPT Assistant
    let endpoint = '/api/send_message_to_assistant/';

    // Set the endpoint differently if not using an assistant
    if (!data.assistant_id) {
        endpoint = '/api/send_message/';
    }

    // Make the API call
    $.ajax({
        url: endpoint,
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(data),
        headers: {
            'X-CSRFToken': window.csrfToken
        },
        success: function(response) {
            // Hide typing indicator
            hideTypingIndicator();

            // Add the assistant's response to the UI
            addMessageToUI('assistant', response.message);

            // Update conversation ID if this was a new conversation
            if (!data.conversation_id) {
                $('#current-conversation-id').val(response.conversation_id);

                // Update the URL without reloading the page
                const newUrl = `/chat/${response.conversation_id}/`;
                history.pushState({}, null, newUrl);

                // Add the new conversation to the sidebar
                addConversationToSidebar(response.conversation_id, response.conversation_title);
            }

            // Re-enable the send button
            $('#send-button').prop('disabled', false);

            // Make sure the message input is empty
            $('#message-input').val('').focus();

            // Scroll to the bottom of the messages
            scrollToBottom();
        },
        error: function(xhr, status, error) {
            console.error('Error sending message:', error);
            hideTypingIndicator();

            // Show error message to user
            addErrorMessageToUI('Ошибка при отправке сообщения. Пожалуйста, попробуйте еще раз.');

            // Re-enable the send button
            $('#send-button').prop('disabled', false);
        }
    });
}

// Main chat functionality
$(document).ready(function() {
    // Initially check for current-conversation-id
    const currentConversationId = $('#current-conversation-id').val();

    // Check for current assistant ID
    currentAssistantId = $('#current-assistant-id').val() || null;

    console.log("Current conversation ID:", currentConversationId);
    console.log("Current assistant ID:", currentAssistantId);

    // Toggle sidebar on button click
    $('#toggle-sidebar, #open-sidebar').on('click', function() {
        $('#sidebar').toggleClass('hidden');
        $('#mobile-header').toggleClass('hidden');
    });

    // File input handler
    $('#file-input').on('change', handleFileSelect);

    // Remove attachment button
    $('#remove-attachment').on('click', function() {
        resetAttachment();
    });

    // Handle clicking the "New Chat" button
    $('#new-chat').on('click', function() {
        // Clear conversation ID and assistant ID
        $('#current-conversation-id').val('');
        currentAssistantId = null;

        // Show empty state UI
        $('#messages').addClass('hidden');
        $('#empty-state').removeClass('hidden');
        $('#input-container').removeClass('hidden');

        // Clear message input
        $('#message-input').val('');

        // Set h1 back to default
        $('#empty-state h1').text('Чем я могу помочь?');

        // Update URL
        history.pushState({}, null, '/chat/');
    });

    // Handle clicking the empty input to start a new chat
    $('#empty-input').on('keydown', function(e) {
        if (e.key === 'Enter') {
            const message = $(this).val().trim();
            if (message) {
                $('#message-input').val(message);
                $(this).val('');

                // Hide empty state
                $('#empty-state').addClass('hidden');

                // Show messages area and input
                $('#messages').removeClass('hidden');
                $('#input-container').removeClass('hidden');

                // Send message using either standard or assistant method
                if (currentAssistantId) {
                    sendMessageToAssistant(message);
                } else {
                    sendMessage(message);
                }
            }
        }
    });

    // Handle message input resize to fit content
    $('#message-input').on('input', function() {
        this.style.height = 'auto';
        this.style.height = (this.scrollHeight) + 'px';

        // Enable/disable send button based on content
        $('#send-button').prop('disabled', !$(this).val().trim() && !selectedFile);
    });

    // Handle message submission via Enter key
    $('#message-input').on('keydown', function(e) {
        // Enter without shift to send
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            $('#send-button').click();
        }
    });

    // Handle pasting from clipboard
    document.addEventListener('paste', handleClipboardPaste);

    // Click handler for paste button
    $('#paste-clipboard').on('click', function() {
        navigator.clipboard.read()
            .then(items => {
                for (const item of items) {
                    for (const type of item.types) {
                        if (type.startsWith('image/')) {
                            item.getType(type).then(blob => {
                                // Create a file from the blob
                                const file = new File([blob], "pasted-image.png", { type: blob.type });
                                // Process the file as if it were selected through the file input
                                selectedFile = file;
                                $('#attachment-preview').removeClass('hidden').addClass('flex');
                                $('#attachment-name').text("Изображение из буфера обмена");
                                $('#send-button').prop('disabled', false);
                                showImagePreview(file);
                            });
                            return;
                        }
                    }
                }
            })
            .catch(err => {
                console.error("Error accessing clipboard: ", err);
                alert("Не удалось получить доступ к буферу обмена. Пожалуйста, используйте кнопку добавления файла.");
            });
    });

    // Handle send button click
    $('#send-button').on('click', function() {
        const message = $('#message-input').val().trim();
        const conversationId = $('#current-conversation-id').val();

        // Only send if there's a message or an attachment
        if (message || selectedFile) {
            // Use the appropriate sending method based on whether we're using an assistant
            if (currentAssistantId) {
                sendMessageToAssistant(message, conversationId);
            } else {
                sendMessage(message, conversationId);
            }

            // Reset input area
            $('#message-input').val('').css('height', 'auto');
            $(this).prop('disabled', true);
        }
    });

    // ... rest of your existing code ...
});

// Функция для инициализации всех обработчиков после загрузки DOM
function initializeHandlers() {
    console.log('Initializing handlers');

    // File input change handler - используем прямой DOM-обработчик вместо jQuery
    const fileInput = document.getElementById('file-input');
    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            console.log('File input change event triggered');
            handleFileSelect(e);
        });
    }

    // Remove attachment button handler
    const removeAttachment = document.getElementById('remove-attachment');
    if (removeAttachment) {
        removeAttachment.addEventListener('click', function() {
            console.log('Remove attachment button clicked');
            removeSelectedFile();
        });
    }

    // Paste button handler
    const pasteButton = document.getElementById('paste-clipboard');
    if (pasteButton) {
        pasteButton.addEventListener('click', function() {
            console.log('Paste clipboard button clicked');
            triggerClipboardPaste();
        });
    }

    // Message input paste handler
    const messageInput = document.getElementById('message-input');
    if (messageInput) {
        messageInput.addEventListener('paste', function(e) {
            console.log('Paste event in message input');
            handleClipboardPaste(e);
        });

        // Global paste handler
        document.addEventListener('paste', function(e) {
            console.log('Global paste event detected');
            if (document.activeElement !== messageInput) {
                handleClipboardPaste(e);
            }
        });
    }

    console.log('All handlers initialized');
}

// Повторно инициализируем обработчики для уверенности
setTimeout(initializeHandlers, 1000);

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

// Добавляем дополнительный код для проверки работы превью изображений
console.log('Testing image preview functionality');

// Проверяем, что все элементы существуют
const imagePreview = document.getElementById('image-preview');
const imagePreviewWrapper = document.getElementById('image-preview-wrapper');
const attachmentPreview = document.getElementById('attachment-preview');

if (imagePreview && imagePreviewWrapper && attachmentPreview) {
    console.log('All preview elements found');
} else {
    console.error('Some preview elements are missing!', {
        imagePreview: !!imagePreview,
        imagePreviewWrapper: !!imagePreviewWrapper,
        attachmentPreview: !!attachmentPreview
    });
}

// Добавляем обработчик для отладки превью изображений
window.testImagePreview = function() {
    console.log('Testing image preview manually');

    // Создаем тестовое изображение
    const canvas = document.createElement('canvas');
    canvas.width = 100;
    canvas.height = 100;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = 'red';
    ctx.fillRect(0, 0, 100, 100);

    // Преобразуем canvas в blob
    canvas.toBlob(function(blob) {
        console.log('Created test image blob');
        const testFile = new File([blob], 'test_image.png', { type: 'image/png' });

        // Устанавливаем как выбранный файл
        selectedFile = testFile;

        // Обновляем UI
        const attachmentPreview = document.getElementById('attachment-preview');
        const attachmentName = document.getElementById('attachment-name');

        if (attachmentPreview && attachmentName) {
            attachmentPreview.classList.remove('hidden');
            attachmentPreview.style.display = 'block';
            attachmentName.textContent = 'Тестовое изображение';

            // Показываем превью
            showImagePreview(testFile);

            console.log('Test image preview should be visible now');
        } else {
            console.error('Attachment preview elements not found');
        }
    });
};

// Запускаем тест превью через 2 секунды после загрузки страницы
setTimeout(function() {
    console.log('Running automatic image preview test');
    window.testImagePreview();
}, 2000);

// Event delegation for sidebar items, including assistants
$(document).on('click', '.assistant-item', function() {
    const assistantId = $(this).data('assistant-id');

    // Set the current assistant ID
    currentAssistantId = assistantId;

    // Clear the current conversation ID
    $('#current-conversation-id').val('');

    // Show empty state
    $('#messages').addClass('hidden');
    $('#empty-state').removeClass('hidden');

    // Update the UI to show this is a conversation with an assistant
    $('#empty-state h1').text(`Чат с ассистентом "${$(this).find('span').text()}"`);

    // Make sure input container is visible
    $('#input-container').removeClass('hidden');

    // Update URL
    history.pushState({}, null, '/chat/');

    // Make sure sidebar is closed on mobile
    if (window.innerWidth < 768) {
        $('#sidebar').addClass('hidden');
        $('#mobile-header').removeClass('hidden');
    }
});
// Function to add user message to UI
function addUserMessageToUI(content, senderName = 'User', attachment = null) {
    const username = senderName || 'User';
    const initial = username.charAt(0).toUpperCase();

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

    const messageHTML = `
        <div class="py-5 -mx-4 px-4">
            <div class="max-w-3xl mx-auto flex">
                <div class="flex-shrink-0 mr-4 mt-1">
                    <div class="w-7 h-7 rounded-full bg-zinc-700 flex items-center justify-center text-white">
                        ${initial}
                    </div>
                </div>
                <div class="flex-1">
                    <div class="flex items-center mb-1">
                        <span class="text-white font-medium">${username}</span>
                    </div>
                    <div class="prose prose-invert max-w-none">
                        <div class="text-white whitespace-pre-wrap">${content}</div>
                        ${attachmentHTML}
                    </div>
                </div>
            </div>
        </div>
    `;

    $('#messages').append(messageHTML);
    scrollToBottom();
}

// Function to add assistant message to UI
function addAssistantMessageToUI(content, senderName = 'ChatGPT') {
    const messageHTML = `
        <div class="py-5 bg-zinc-800/40 -mx-4 px-4">
            <div class="max-w-3xl mx-auto flex">
                <div class="flex-shrink-0 mr-4 mt-1">
                    <div class="w-7 h-7 rounded-full bg-[#19c37d] flex items-center justify-center">
                        <svg width="24" height="24" viewBox="0 0 24 24"
                             xmlns="http://www.w3.org/2000/svg">
                            <path d="M22.2819 9.8211a5.9847 5.9847 0 0 0-.5157-4.9108 6.0462 6.0462 0 0 0-6.5098-2.9A6.0651 6.0651 0 0 0 4.9807 4.1818a5.9847 5.9847 0 0 0-3.9977 2.9 6.0462 6.0462 0 0 0 .7427 7.0966 5.98 5.98 0 0 0 .511 4.9107 6.051 6.051 0 0 0 6.5146 2.9001A5.9847 5.9847 0 0 0 13.2599 24a6.0557 6.0557 0 0 0 5.7718-4.2058 5.9894 5.9894 0 0 0 3.9977-2.9001 6.0557 6.0557 0 0 0-.7475-7.0729zm-9.022 12.6081a4.4755 4.4755 0 0 1-2.8764-1.0408l.1419-.0804 4.7783-2.7582a.7948.7948 0 0 0 .3927-.6813v-6.7369l2.02 1.1686a.071.071 0 0 1 .038.052v5.5826a4.504 4.504 0 0 1-4.4945 4.4944zm-9.6607-4.1254a4.4708 4.4708 0 0 1-.5346-3.0137l.142.0852 4.783 2.7582a.7712.7712 0 0 0 1.5612 0l5.8428-3.3685v2.3324a.0804.0804 0 0 1-.0332.0615L9.74 19.9502a4.4992 4.4992 0 0 1-6.1408-1.6464zM2.3408 7.8956a4.485 4.485 0 0 1 2.3655-1.9728V11.6a.7664.7664 0 0 0 .3879.6765l5.8144 3.3543-2.0201 1.1685a.0757.0757 0 0 1-.142 0l-4.8303-2.7865A4.504 4.504 0 0 1 2.3408 7.872zm16.5963 3.8558L13.1038 8.364 15.1192 7.2a.0757.0757 0 0 1 .142 0l4.8303 2.7913a4.4944 4.4944 0 0 1-.6765 8.1042v-5.6772a.79.79 0 0 0-.407-.667zm2.0107-3.0231l-.142-.0852-4.7735-2.7818a.7759.7759 0 0 0-.7854 0L9.409 9.2297V6.8974a.0662.0662 0 0 1 .0284-.0615l4.8303-2.7866a4.4992 4.4992 0 0 1 6.6802 4.66zM8.3065 12.863l-2.02-1.1638a.0804.0804 0 0 1-.038-.0567V6.0742a4.4992 4.4992 0 0 1 7.3757-3.4537l-.142.0805L8.704 5.459a.7948.7948 0 0 0-.3927.6813v13.5zm1.0976-2.3654l2.602-1.4998 2.6069 1.4998v2.9994l-2.5974 1.5087-2.6067-1.4997v-6.0168z"
                                  fill="#FFF"/>
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

    $('#messages').append(messageHTML);
    scrollToBottom();
}

// Function to show typing indicator
function showTypingIndicator() {
    $('#messages').append(`
        <div id="typing-indicator" class="py-5 bg-zinc-800/40 -mx-4 px-4">
            <div class="max-w-3xl mx-auto flex">
                <div class="flex-shrink-0 mr-4 mt-1">
                    <div class="w-7 h-7 rounded-full bg-[#19c37d] flex items-center justify-center">
                        <svg width="24" height="24" viewBox="0 0 24 24"
                             xmlns="http://www.w3.org/2000/svg">
                            <path d="M22.2819 9.8211a5.9847 5.9847 0 0 0-.5157-4.9108 6.0462 6.0462 0 0 0-6.5098-2.9A6.0651 6.0651 0 0 0 4.9807 4.1818a5.9847 5.9847 0 0 0-3.9977 2.9 6.0462 6.0462 0 0 0 .7427 7.0966 5.98 5.98 0 0 0 .511 4.9107 6.051 6.051 0 0 0 6.5146 2.9001A5.9847 5.9847 0 0 0 13.2599 24a6.0557 6.0557 0 0 0 5.7718-4.2058 5.9894 5.9894 0 0 0 3.9977-2.9001 6.0557 6.0557 0 0 0-.7475-7.0729zm-9.022 12.6081a4.4755 4.4755 0 0 1-2.8764-1.0408l.1419-.0804 4.7783-2.7582a.7948.7948 0 0 0 .3927-.6813v-6.7369l2.02 1.1686a.071.071 0 0 1 .038.052v5.5826a4.504 4.504 0 0 1-4.4945 4.4944zm-9.6607-4.1254a4.4708 4.4708 0 0 1-.5346-3.0137l.142.0852 4.783 2.7582a.7712.7712 0 0 0 1.5612 0l5.8428-3.3685v2.3324a.0804.0804 0 0 1-.0332.0615L9.74 19.9502a4.4992 4.4992 0 0 1-6.1408-1.6464zM2.3408 7.8956a4.485 4.485 0 0 1 2.3655-1.9728V11.6a.7664.7664 0 0 0 .3879.6765l5.8144 3.3543-2.0201 1.1685a.0757.0757 0 0 1-.142 0l-4.8303-2.7865A4.504 4.504 0 0 1 2.3408 7.872zm16.5963 3.8558L13.1038 8.364 15.1192 7.2a.0757.0757 0 0 1 .142 0l4.8303 2.7913a4.4944 4.4944 0 0 1-.6765 8.1042v-5.6772a.79.79 0 0 0-.407-.667zm2.0107-3.0231l-.142-.0852-4.7735-2.7818a.7759.7759 0 0 0-.7854 0L9.409 9.2297V6.8974a.0662.0662 0 0 1 .0284-.0615l4.8303-2.7866a4.4992 4.4992 0 0 1 6.6802 4.66zM8.3065 12.863l-2.02-1.1638a.0804.0804 0 0 1-.038-.0567V6.0742a4.4992 4.4992 0 0 1 7.3757-3.4537l-.142.0805L8.704 5.459a.7948.7948 0 0 0-.3927.6813v13.5zm1.0976-2.3654l2.602-1.4998 2.6069 1.4998v2.9994l-2.5974 1.5087-2.6067-1.4997v-6.0168z"
                                  fill="#FFF"/>
                        </svg>
                    </div>
                </div>
                <div class="flex-1">
                    <div class="flex items-center mb-1">
                        <span class="text-white font-medium">${currentAssistantId ? 'Ассистент' : 'ChatGPT'}</span>
                    </div>
                    <div class="flex space-x-2 items-center">
                        <div class="h-2 w-2 bg-zinc-400 rounded-full animate-pulse"></div>
                        <div class="h-2 w-2 bg-zinc-400 rounded-full animate-pulse delay-150"></div>
                        <div class="h-2 w-2 bg-zinc-400 rounded-full animate-pulse delay-300"></div>
                    </div>
                </div>
            </div>
        </div>
    `);
    scrollToBottom();
}

// Function to hide typing indicator
function hideTypingIndicator() {
    $('#typing-indicator').remove();
}

// Function to add error message to UI
function addErrorMessageToUI(message) {
    $('#messages').append(`
        <div class="py-5 bg-zinc-800/40 -mx-4 px-4">
            <div class="max-w-3xl mx-auto flex">
                <div class="flex-1">
                    <div class="prose prose-invert max-w-none">
                        <div class="text-red-500 whitespace-pre-wrap">${message}</div>
                    </div>
                </div>
            </div>
        </div>
    `);
    scrollToBottom();
}

// Function to scroll to bottom of messages container
function scrollToBottom() {
    const messagesContainer = document.getElementById('messages-container');
    if (messagesContainer) {
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }
}

// Function to reset attachment UI and data
function resetAttachment() {
    selectedFile = null;
    $('#attachment-preview').addClass('hidden').removeClass('flex');
    $('#image-preview-wrapper').addClass('hidden');
    $('#image-preview').attr('src', '');
    $('#attachment-name').text('');
    $('#file-input').val('');

    // Disable send button if message input is empty
    if (!$('#message-input').val().trim()) {
        $('#send-button').prop('disabled', true);
    }
}
