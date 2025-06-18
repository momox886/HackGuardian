  const socket = io();
  const username = "{{ user.email|e }}";
  const userId = "{{ user.id }}";

  let currentRoom = null;
  let currentRoomDomId = null;

  function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
  }

  function selectUser(targetId, targetEmail) {
    const newRoom = userId < targetId ? `dm_${userId}_${targetId}` : `dm_${targetId}_${userId}`;

    if (currentRoom) {
      socket.emit('leave', { room: currentRoom });
      document.getElementById(currentRoomDomId)?.classList.remove('active');
    }

    currentRoom = newRoom;
    currentRoomDomId = `user_${targetId}`;
    socket.emit('join', { room: currentRoom });
    document.getElementById(currentRoomDomId).classList.add('active');
    document.getElementById('chat-box').innerHTML = "";
    document.getElementById('chat-header').textContent = `Conversation avec ${escapeHtml(targetEmail)}`;
    document.getElementById('back-btn').style.display = "block";

    if (window.innerWidth <= 768) {
      document.getElementById('sidebar').classList.remove('show');
    }

    fetch(`/get_messages/${newRoom}`)
      .then(res => res.json())
      .then(messages => {
        messages.forEach(msg => {
          const msgElement = document.createElement("div");
          msgElement.classList.add("message");
          msgElement.classList.add(msg.sender_email === username ? "message-right" : "message-left");
          msgElement.innerHTML = `<span>${escapeHtml(msg.content)}</span>`;
          document.getElementById("chat-box").appendChild(msgElement);
        });
        document.getElementById("chat-box").scrollTop = document.getElementById("chat-box").scrollHeight;
      });
  }

  function goBack() {
    currentRoom = null;
    document.getElementById("chat-box").innerHTML = "";
    document.getElementById("chat-header").textContent = "Sélectionnez un utilisateur";
    document.getElementById("back-btn").style.display = "none";

    if (window.innerWidth <= 768) {
      document.getElementById("sidebar").classList.add("show");
    }
  }

  socket.on("receive_message", function(data) {
    const msgElement = document.createElement("div");
    msgElement.classList.add("message");
    msgElement.classList.add(data.username === username ? "message-right" : "message-left");
    msgElement.innerHTML = `<span>${escapeHtml(data.message)}</span>`;
    document.getElementById("chat-box").appendChild(msgElement);
    document.getElementById("chat-box").scrollTop = document.getElementById("chat-box").scrollHeight;
  });

  function sendMessage() {
    const input = document.getElementById("message-input");
    const message = input.value.trim();
    if (message && currentRoom) {
      socket.emit("send_message", {
        username: username,
        user_id: userId,
        message: message,
        room: currentRoom
      });
      input.value = "";
    }
  }

  document.getElementById("message-input").addEventListener("keydown", function(e) {
    if (e.key === "Enter") sendMessage();
  });
