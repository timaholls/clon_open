/**
 * ChatGPT Clone - Chat functionality
 * Uses the Auth module for authenticated API requests
 */

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

// Templates for chat UI elements
function getUserMessageHTML(content) {
    return `
        <div class="py-5 -mx-4 px-4">
            <div class="max-w-3xl mx-auto flex">
                <div class="flex-shrink-0 mr-4 mt-1">
                    <div class="w-7 h-7 rounded-full bg-zinc-700 flex items-center justify-center text-white">
                        У
                    </div>
                </div>
                <div class="flex-1">
                    <div class="prose prose-invert max-w-none">
                        <div class="text-white whitespace-pre-wrap">${content}</div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function getAssistantMessageHTML(content) {
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
            <span class="truncate flex-1">${title}</span>
            <button class="delete-conversation ml-auto text-zinc-500 opacity-0 hover:opacity-100 hover:text-zinc-300 px-1">
                <i class="ri-delete-bin-line"></i>
            </button>
        </div>
    `;
}

// Main chat functionality
$(document).ready(function() {
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
                if (response.status === 401 || response.status === 403) {
                    // Redirect to login
                    window.location.href = '/login/';
                    throw new Error('Authentication failed');
                }
                return response;
            });
    }

    // Function to load a conversation
    function loadConversation(conversationId) {
        // Clear current messages
        $messages.empty();

        // Hide empty state, show messages and input
        $emptyState.hide();
        $messages.show();
        $inputContainer.show();

        // Highlight the selected conversation in sidebar
        $('.sidebar-item').removeClass('active');
        $(`.sidebar-item[data-conversation-id="${conversationId}"]`).addClass('active');

        // Set current conversation ID
        setCurrentConversationId(conversationId);

        // Fetch conversation messages from server with auth
        fetchWithAuth(`/api/conversations/${conversationId}/messages/`)
            .then(response => response.json())
            .then(data => {
                // Add each message to the chat
                data.messages.forEach(function(msg) {
                    if (msg.role === 'user') {
                        $messages.append(getUserMessageHTML(msg.content));
                    } else {
                        $messages.append(getAssistantMessageHTML(msg.content));
                    }
                });

                // Scroll to bottom
                $messagesContainer.scrollTop($messagesContainer[0].scrollHeight);
            })
            .catch(error => {
                console.error('Error loading conversation:', error);
                $messages.html('<div class="text-red-500 p-4">Ошибка загрузки чата. Пожалуйста, попробуйте еще раз.</div>');
            });
    }

    // Function to create a new conversation
    function createNewConversation() {
        fetchWithAuth('/api/conversations/create/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.json())
        .then(data => {
            // Add to sidebar list
            $conversationsList.prepend(getConversationItemHTML(data.id, data.title));

            // Start new chat with this conversation
            startNewChat();
            setCurrentConversationId(data.id);

            // Update sidebar UI
            $('.sidebar-item').removeClass('active');
            $(`.sidebar-item[data-conversation-id="${data.id}"]`).addClass('active');
        })
        .catch(error => {
            console.error('Error creating conversation:', error);
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

    // Function to send message to the server and display response
    function sendMessage(message) {
        if (!message) return;

        const conversationId = getCurrentConversationId();

        // Add user message to the chat
        $messages.append(getUserMessageHTML(message));

        // Clear and reset input field
        $messageInput.val('').trigger('input');
        $messageInput.css('height', 'auto');

        // Scroll to bottom
        $messagesContainer.scrollTop($messagesContainer[0].scrollHeight);

        // Add thinking animation
        $messages.append(getThinkingMessageHTML());
        $messagesContainer.scrollTop($messagesContainer[0].scrollHeight);

        // Send to server with auth
        fetchWithAuth('/api/send_message/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrftoken')
            },
            body: JSON.stringify({
                message: message,
                conversation_id: conversationId
            })
        })
        .then(response => response.json())
        .then(response => {
            // Remove thinking animation
            $('#thinking').remove();

            // Add assistant response
            $messages.append(getAssistantMessageHTML(response.message));

            // Update conversation ID if needed (new conversation)
            if (!conversationId) {
                setCurrentConversationId(response.conversation_id);

                // Add to sidebar if not already there
                if ($(`.sidebar-item[data-conversation-id="${response.conversation_id}"]`).length === 0) {
                    $conversationsList.prepend(getConversationItemHTML(response.conversation_id, response.conversation_title));

                    // Update sidebar UI
                    $('.sidebar-item').removeClass('active');
                    $(`.sidebar-item[data-conversation-id="${response.conversation_id}"]`).addClass('active');
                }
            }

            // Scroll to bottom
            $messagesContainer.scrollTop($messagesContainer[0].scrollHeight);

            // Log to console (as requested)
            console.log("Received message:", message);
            console.log("Response:", response.message);
        })
        .catch(error => {
            // Remove thinking animation
            $('#thinking').remove();

            // Show error message
            $messages.append(getAssistantMessageHTML('Извините, произошла ошибка. Пожалуйста, попробуйте еще раз.'));

            // Scroll to bottom
            $messagesContainer.scrollTop($messagesContainer[0].scrollHeight);

            console.error('Error:', error);
        });
    }

    // Handle sidebar toggle
    $('#toggle-sidebar').on('click', function() {
        $sidebar.toggleClass('hidden');
        if ($sidebar.hasClass('hidden')) {
            $mobileHeader.removeClass('hidden').addClass('flex');
        }
    });

    // Handle mobile sidebar open
    $('#open-sidebar').on('click', function() {
        $sidebar.removeClass('hidden');
        $mobileHeader.removeClass('flex').addClass('hidden');
    });

    // Handle new chat button click
    $('#new-chat').on('click', function() {
        createNewConversation();
    });

    // Handle sidebar item click (to load conversation)
    $(document).on('click', '.sidebar-item', function(e) {
        // Ignore clicks on delete button
        if ($(e.target).closest('.delete-conversation').length) {
            return;
        }

        const conversationId = $(this).data('conversation-id');
        if (conversationId) {
            loadConversation(conversationId);
        }
    });

    // Handle delete conversation button click
    $(document).on('click', '.delete-conversation', function(e) {
        e.stopPropagation();
        const conversationId = $(this).closest('.sidebar-item').data('conversation-id');

        if (confirm('Вы действительно хотите удалить этот чат?')) {
            deleteConversation(conversationId);
        }
    });

    // Handle empty input in hero section
    $emptyInput.on('keydown', function(e) {
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
                setTimeout(function() {
                    sendMessage(message);
                }, 100);

                $(this).val('');
            }
        }
    });

    // Enable/disable send button based on input
    $messageInput.on('input', function() {
        $sendButton.prop('disabled', !$(this).val().trim());
    });

    // Adjust textarea height as user types
    $messageInput.on('input', function() {
        this.style.height = 'auto';
        this.style.height = (this.scrollHeight) + 'px';
    });

    // Handle message submission via button
    $sendButton.on('click', function() {
        sendMessage($messageInput.val().trim());
    });

    // Handle message submission via Enter key
    $messageInput.on('keydown', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            const message = $(this).val().trim();
            if (message) {
                sendMessage(message);
            }
        }
    });

    // Handle copy button clicks
    $(document).on('click', '.copy-btn', function() {
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
        setTimeout(function() {
            $icon.removeClass('ri-check-line').addClass('ri-file-copy-line');
        }, 2000);
    });

    // Handle thumbs up/down clicks
    $(document).on('click', '.thumbs-up-btn, .thumbs-down-btn', function() {
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
        $logoutButton.on('click', function(e) {
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
