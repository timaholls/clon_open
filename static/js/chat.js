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
                                $('#attachment-preview').removeClass('hidden').addClass('flex');
                                $('#attachment-name').text('Изображение из буфера обмена');
                                $('#send-button').prop('disabled', false);
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
                                $('#attachment-preview').removeClass('hidden').addClass('flex');
                                $('#attachment-name').text('Документ из буфера обмена');
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

// Function to scroll to bottom of messages container
function scrollToBottom() {
    const messagesContainer = document.getElementById('messages');
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
                resolve(getCookie('csrftoken'));
            })
            .catch(error => {
                console.error('Error refreshing CSRF token:', error);
                reject(error);
            });
    });
}

// Function to display user messages with attachment support
function getUserMessageHTML(content, senderName = 'Пользователь', attachment = null) {
    const firstLetter = senderName.charAt(0).toUpperCase();
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

// Function to display assistant messages
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

// Function to show typing indicator
function showTypingIndicator() {
    $('#messages').append(`
        <div id="typing-indicator" class="py-5 bg-zinc-800/40 -mx-4 px-4">
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

// Function to add message to UI
function addMessageToUI(role, content, attachment = null) {
    $('#empty-state').addClass('hidden');
    $('#messages').removeClass('hidden');
    if (role === 'user') {
        let attachmentObj = null;
        if (attachment) {
            const isImage = attachment.type.startsWith('image/');
            const reader = new FileReader();
            reader.onload = function(e) {
                attachmentObj = {
                    name: attachment.name,
                    type: isImage ? 'image' : 'file',
                    url: e.target.result
                };
                const userHtml = getUserMessageHTML(content, 'Пользователь', attachmentObj);
                $('#messages').append(userHtml);
                scrollToBottom();
            };
            reader.readAsDataURL(attachment);
        } else {
            const userHtml = getUserMessageHTML(content);
            $('#messages').append(userHtml);
            scrollToBottom();
        }
    } else if (role === 'assistant') {
        const assistantHtml = getAssistantMessageHTML(content);
        $('#messages').append(assistantHtml);
        scrollToBottom();
    }
}

// Function to send message to standard ChatGPT (non-assistant mode)
function sendMessage(message, conversationId = null) {
    $('#send-button').prop('disabled', true);
    const data = {
        message: message,
        conversation_id: conversationId
    };
    if (selectedFile) {
        data.has_attachment = true;
    }
    sendMessageWithData(data, selectedFile);
}

// Function to send message to assistant
function sendMessageToAssistant(message, conversationId = null) {
    $('#send-button').prop('disabled', true);
    const data = {
        message: message,
        conversation_id: conversationId,
        assistant_id: currentAssistantId
    };
    if (selectedFile) {
        data.has_attachment = true;
    }
    sendMessageWithData(data, selectedFile);
}

// Function to add a new conversation to the sidebar
function addConversationToSidebar(id, title) {
    if (!id || !title) return;
    const conversationHtml = getConversationItemHTML(id, title);
    $('#conversations-list').prepend(conversationHtml);
    $('.sidebar-item[data-conversation-id="' + id + '"]').click(function() {
        const conversationId = $(this).data('conversation-id');
        window.location.href = '/chat/' + conversationId + '/';
    });
}

// Function to send the API request
function sendMessageWithData(data, file = null) {
    addMessageToUI('user', data.message, file);
    resetAttachment();
    showTypingIndicator();
    let endpoint = data.assistant_id ? '/api/send_message_to_assistant/' : '/api/send_message/';
    let ajaxOptions = {
        url: endpoint,
        type: 'POST',
        headers: {
            'X-CSRFToken': getCookie('csrftoken')
        },
        success: function(response) {
            hideTypingIndicator();
            addMessageToUI('assistant', response.message);
            if (!data.conversation_id) {
                $('#current-conversation-id').val(response.conversation_id);
                const newUrl = `/chat/${response.conversation_id}/`;
                history.pushState({}, null, newUrl);
                addConversationToSidebar(response.conversation_id, response.conversation_title);
            }
            $('#send-button').prop('disabled', false);
            $('#message-input').val('').focus();
            scrollToBottom();
        },
        error: function(xhr, status, error) {
            console.error('Error sending message:', error);
            hideTypingIndicator();
            addErrorMessageToUI('Ошибка при отправке сообщения. Пожалуйста, попробуйте еще раз.');
            $('#send-button').prop('disabled', false);
        }
    };
    if (file) {
        let formData = new FormData();
        formData.append('message', data.message);
        formData.append('conversation_id', data.conversation_id || '');
        if (data.assistant_id) {
            formData.append('assistant_id', data.assistant_id);
        }
        formData.append('attachment', file);
        ajaxOptions.processData = false;
        ajaxOptions.contentType = false;
        ajaxOptions.data = formData;
    } else {
        ajaxOptions.contentType = 'application/json';
        ajaxOptions.data = JSON.stringify(data);
    }
    $.ajax(ajaxOptions);
}

// Main chat functionality
$(document).ready(function() {
    scrollToBottom();
    $(window).on('resize', function() {
        scrollToBottom();
    });
    if (typeof MutationObserver !== 'undefined') {
        const messagesElement = document.getElementById('messages');
        if (messagesElement) {
            const observer = new MutationObserver(function() {
                scrollToBottom();
            });
            observer.observe(messagesElement, {
                childList: true,
                subtree: true
            });
        }
    }
    const currentConversationId = $('#current-conversation-id').val();
    currentAssistantId = $('#current-assistant-id').val() || null;
    console.log("Current conversation ID:", currentConversationId);
    console.log("Current assistant ID:", currentAssistantId);
    $('#toggle-sidebar, #open-sidebar').on('click', function() {
        $('#sidebar').toggleClass('hidden');
        $('#mobile-header').toggleClass('hidden');
    });
    $('#file-input').on('change', handleFileSelect);
    $('#remove-attachment').on('click', function() {
        resetAttachment();
    });
    $('#new-chat').on('click', function() {
        $('#current-conversation-id').val('');
        currentAssistantId = null;
        $('#messages').addClass('hidden');
        $('#empty-state').removeClass('hidden');
        $('#input-container').removeClass('hidden');
        $('#message-input').val('');
        $('#empty-state h1').text('Чем я могу помочь?');
        history.pushState({}, null, '/chat/');
    });
    $('#empty-input').on('keydown', function(e) {
        if (e.key === 'Enter') {
            const message = $(this).val().trim();
            if (message) {
                $('#message-input').val(message);
                $(this).val('');
                $('#empty-state').addClass('hidden');
                $('#messages').removeClass('hidden');
                $('#input-container').removeClass('hidden');
                if (currentAssistantId) {
                    sendMessageToAssistant(message);
                } else {
                    sendMessage(message);
                }
            }
        }
    });
    $('#message-input').on('input', function() {
        this.style.height = 'auto';
        this.style.height = (this.scrollHeight) + 'px';
        $('#send-button').prop('disabled', !$(this).val().trim() && !selectedFile);
    });
    $('#message-input').on('keydown', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            $('#send-button').click();
        }
    });
    document.addEventListener('paste', handleClipboardPaste);
    $('#paste-clipboard').on('click', function() {
        triggerClipboardPaste();
    });
    $('#send-button').on('click', function() {
        const message = $('#message-input').val().trim();
        const conversationId = $('#current-conversation-id').val();
        if (message || selectedFile) {
            if (currentAssistantId) {
                sendMessageToAssistant(message, conversationId);
            } else {
                sendMessage(message, conversationId);
            }
            $('#message-input').val('').css('height', 'auto');
            $(this).prop('disabled', true);
        }
    });
    initializeHandlers();
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
});

// Function to initialize all handlers after DOM load
function initializeHandlers() {
    console.log('Initializing handlers');
    const fileInput = document.getElementById('file-input');
    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            console.log('File input change event triggered');
            handleFileSelect(e);
        });
    }
    const removeAttachment = document.getElementById('remove-attachment');
    if (removeAttachment) {
        removeAttachment.addEventListener('click', function() {
            console.log('Remove attachment button clicked');
            removeSelectedFile();
        });
    }
    const pasteButton = document.getElementById('paste-clipboard');
    if (pasteButton) {
        pasteButton.addEventListener('click', function() {
            console.log('Paste clipboard button clicked');
            triggerClipboardPaste();
        });
    }
    const messageInput = document.getElementById('message-input');
    if (messageInput) {
        messageInput.addEventListener('paste', function(e) {
            console.log('Paste event in message input');
            handleClipboardPaste(e);
        });
        document.addEventListener('paste', function(e) {
            console.log('Global paste event detected');
            if (document.activeElement !== messageInput) {
                handleClipboardPaste(e);
            }
        });
    }
    console.log('All handlers initialized');
}

// Event delegation for assistant items in sidebar
$(document).on('click', '.assistant-item', function() {
    const assistantId = $(this).data('assistant-id');
    currentAssistantId = assistantId;
    $('#current-conversation-id').val('');
    $('#messages').addClass('hidden');
    $('#empty-state').removeClass('hidden');
    $('#empty-state h1').text(`Чат с ассистентом "${$(this).find('span').text()}"`);
    $('#input-container').removeClass('hidden');
    history.pushState({}, null, '/chat/');
    if (window.innerWidth < 768) {
        $('#sidebar').addClass('hidden');
        $('#mobile-header').removeClass('hidden');
    }
});

// Function to reset attachment UI and data
function resetAttachment() {
    selectedFile = null;
    $('#attachment-preview').addClass('hidden').removeClass('flex');
    $('#image-preview-wrapper').addClass('hidden');
    $('#image-preview').attr('src', '');
    $('#attachment-name').text('');
    $('#file-input').val('');
    if (!$('#message-input').val().trim()) {
        $('#send-button').prop('disabled', true);
    }
}

// Function to create conversation item HTML
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