document.addEventListener('DOMContentLoaded', function () {
    const chatWidget = document.getElementById('chat-widget');
    const chatToggle = document.getElementById('chat-toggle');
    const chatClose = document.getElementById('chat-close');
    const chatMessages = document.getElementById('chat-messages');
    const chatInput = document.getElementById('chat-input');
    const chatSend = document.getElementById('chat-send');

    // Toggle Chat
    chatToggle.addEventListener('click', () => {
        chatWidget.classList.toggle('d-none');
    });

    chatClose.addEventListener('click', () => {
        chatWidget.classList.add('d-none');
    });

    // Send Message
    async function sendMessage() {
        const message = chatInput.value.trim();
        if (!message) return;

        // User Message
        appendMessage('user', message);
        chatInput.value = '';

        // Show "Thinking..."
        const loadingMsg = appendMessage('bot', "Thinking...");
        chatInput.disabled = true;
        chatSend.disabled = true;

        try {
            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message: message }),
            });

            const data = await response.json();

            // Remove "Thinking..." and show actual response
            loadingMsg.remove();
            appendMessage('bot', data.response);

        } catch (error) {
            console.error('Error:', error);
            loadingMsg.remove();
            appendMessage('bot', "Sorry, I'm having trouble connecting to my brain right now. Please try again in 1-2 minutes.");
        } finally {
            chatInput.disabled = false;
            chatSend.disabled = false;
            chatInput.focus();
        }
    }

    chatSend.addEventListener('click', sendMessage);
    chatInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });

    function appendMessage(sender, text) {
        const msgDiv = document.createElement('div');
        msgDiv.classList.add('chat-message', sender === 'user' ? 'text-end' : 'text-start', 'mb-2');

        const bubble = document.createElement('div');
        bubble.classList.add('d-inline-block', 'p-2', 'rounded');

        if (sender === 'user') {
            bubble.classList.add('bg-primary', 'text-white');
            bubble.style.borderRadius = '15px 15px 0 15px';
        } else {
            bubble.classList.add('bg-light', 'text-dark', 'border');
            bubble.style.borderRadius = '15px 15px 15px 0';
        }

        bubble.textContent = text;
        msgDiv.appendChild(bubble);
        chatMessages.appendChild(msgDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
});
