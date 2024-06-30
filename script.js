document.addEventListener("DOMContentLoaded", function () {
  const messages = document.getElementById("messages");
  const messageInput = document.getElementById("message-input");
  const sendButton = document.getElementById("send-button");

  // Replace with the actual server address and port
  const ws = new WebSocket("ws://localhost:8080");

  ws.onopen = () => {
    console.log("Connected to the server");
  };

  ws.onmessage = (event) => {
    const message = document.createElement("div");
    message.textContent = event.data;
    messages.appendChild(message);
  };

  ws.onclose = () => {
    console.log("Disconnected from the server");
  };

  ws.onerror = (error) => {
    console.error("WebSocket error:", error);
  };

  sendButton.addEventListener("click", () => {
    const message = messageInput.value;
    if (message) {
      ws.send(message);
      messageInput.value = "";
    }
  });

  messageInput.addEventListener("keypress", (event) => {
    if (event.key === "Enter") {
      sendButton.click();
    }
  });
});
