/**
 * Auth utilities for token-based authentication
 */

const Auth = {
    /**
     * Store the token in local storage
     * @param {string} token - The authentication token
     * @param {string} expiresAt - ISO date string of expiration
     */
    setToken: function(token, expiresAt) {
        localStorage.setItem('authToken', token);
        localStorage.setItem('tokenExpiry', expiresAt);

        // Also set in a cookie for server-side access
        document.cookie = `auth_token=${token}; path=/; expires=${new Date(expiresAt).toUTCString()}`;
    },

    /**
     * Get the token from local storage
     * @returns {string|null} The stored token or null if not found
     */
    getToken: function() {
        return localStorage.getItem('authToken');
    },

    /**
     * Check if the token is valid and not expired
     * @returns {boolean} True if the token is valid and not expired
     */
    isTokenValid: function() {
        const token = this.getToken();
        const expiry = localStorage.getItem('tokenExpiry');

        if (!token || !expiry) {
            return false;
        }

        // Check if token is expired
        const expiryDate = new Date(expiry);
        const now = new Date();

        return expiryDate > now;
    },

    /**
     * Clear the authentication data
     */
    clearToken: function() {
        localStorage.removeItem('authToken');
        localStorage.removeItem('tokenExpiry');

        // Clear cookie as well
        document.cookie = 'auth_token=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
    },

    /**
     * Add the token to headers for API requests
     * @param {Object} options - The fetch options object
     * @returns {Object} Updated options with auth headers
     */
    addAuthHeaders: function(options) {
        const token = this.getToken();
        if (!token) {
            return options;
        }

        // Initialize headers if not present
        if (!options.headers) {
            options.headers = {};
        }

        // Add Authorization header
        options.headers['Authorization'] = `Token ${token}`;

        // Ensure credentials are included
        options.credentials = 'include';

        return options;
    },

    /**
     * Perform API request with auth headers
     * @param {string} url - The API endpoint
     * @param {Object} options - The fetch options
     * @returns {Promise} Fetch promise
     */
    fetchWithAuth: function(url, options = {}) {
        // Add CSRF token from cookie for POST requests
        if ((options.method === 'POST' || !options.method) && !url.includes('/api/')) {
            if (!options.headers) {
                options.headers = {};
            }
            const csrftoken = this.getCookie('csrftoken');
            if (csrftoken) {
                options.headers['X-CSRFToken'] = csrftoken;
            }
        }

        return fetch(url, this.addAuthHeaders(options))
            .then(response => {
                // Handle unauthorized or forbidden responses
                if (response.status === 401 || response.status === 403) {
                    // Clear token and redirect to login
                    this.clearToken();
                    window.location.href = '/login/';
                    throw new Error('Authentication failed');
                }
                return response;
            });
    },

    /**
     * Get a cookie by name
     * @param {string} name - The cookie name
     * @returns {string|null} The cookie value or null if not found
     */
    getCookie: function(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                // Does this cookie string begin with the name we want?
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    },

    /**
     * Login using API
     * @param {string} email - User email
     * @param {string} password - User password
     * @returns {Promise} Promise with login result
     */
    login: function(email, password) {
        // Get CSRF token
        const csrftoken = this.getCookie('csrftoken');

        const headers = {
            'Content-Type': 'application/json'
        };

        if (csrftoken) {
            headers['X-CSRFToken'] = csrftoken;
        }

        return fetch('/api/login/', {
            method: 'POST',
            headers: headers,
            credentials: 'include',
            body: JSON.stringify({ email, password })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Login failed');
            }
            return response.json();
        })
        .then(data => {
            // Store token and expiry
            this.setToken(data.token, data.expires_at);
            return data;
        });
    },

    /**
     * Register a new user
     * @param {string} username - Username
     * @param {string} email - User email
     * @param {string} password - User password
     * @returns {Promise} Promise with signup result
     */
    signup: function(username, email, password) {
        // Get CSRF token
        const csrftoken = this.getCookie('csrftoken');

        const headers = {
            'Content-Type': 'application/json'
        };

        if (csrftoken) {
            headers['X-CSRFToken'] = csrftoken;
        }

        return fetch('/api/signup/', {
            method: 'POST',
            headers: headers,
            credentials: 'include',
            body: JSON.stringify({ username, email, password })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Signup failed');
            }
            return response.json();
        })
        .then(data => {
            // Store token and expiry
            this.setToken(data.token, data.expires_at);
            return data;
        });
    },

    /**
     * Logout the user
     */
    logout: function() {
        // Get CSRF token
        const csrftoken = this.getCookie('csrftoken');

        // Call logout API
        fetch('/logout/', {
            method: 'POST',
            headers: {
                'X-CSRFToken': csrftoken || ''
            },
            credentials: 'include'
        }).catch(err => console.error('Logout error:', err));

        // Clear token
        this.clearToken();

        // Redirect to login page
        window.location.href = '/login/';
    }
};

// Check authentication only on login and signup pages
document.addEventListener('DOMContentLoaded', function() {
    // Check if we're on a login or signup page
    const currentPath = window.location.pathname;
    if (currentPath === '/login/' || currentPath === '/signup/') {
        // Check if token is valid and redirect to chat if so
        if (Auth.isTokenValid()) {
            window.location.href = '/';
        }
    }
});

// Add authentication to forms
if (document.getElementById('login-form')) {
    document.getElementById('login-form').addEventListener('submit', function(e) {
        e.preventDefault();

        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;

        Auth.login(email, password)
            .then(() => {
                window.location.href = '/';
            })
            .catch(error => {
                const errorElement = document.getElementById('login-error');
                if (errorElement) {
                    errorElement.textContent = 'Login failed. Please check your credentials.';
                    errorElement.classList.remove('hidden');
                }
            });
    });
}

if (document.getElementById('signup-form')) {
    document.getElementById('signup-form').addEventListener('submit', function(e) {
        e.preventDefault();

        const username = document.getElementById('username').value;
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const passwordConfirm = document.getElementById('password_confirm').value;

        // Check if passwords match
        if (password !== passwordConfirm) {
            const errorElement = document.getElementById('signup-error');
            if (errorElement) {
                errorElement.textContent = 'Passwords do not match.';
                errorElement.classList.remove('hidden');
            }
            return;
        }

        Auth.signup(username, email, password)
            .then(() => {
                window.location.href = '/';
            })
            .catch(error => {
                const errorElement = document.getElementById('signup-error');
                if (errorElement) {
                    errorElement.textContent = 'Signup failed. Please try again.';
                    errorElement.classList.remove('hidden');
                }
            });
    });
}
