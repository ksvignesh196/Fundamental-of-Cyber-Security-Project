import random
import math
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from flask import Flask, render_template, request, session, redirect, url_for
from flask_socketio import join_room, leave_room, send, SocketIO
from string import ascii_uppercase

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
socketio = SocketIO(app)

rooms = {}

# RSA
def generate_prime():
    while True:
        a = random.randint(20, 100)
        if all(a % i != 0 for i in range(2, a)):
            return a

p = generate_prime()
q = generate_prime()
while (q == p):
    q = generate_prime()

n = p * q
phi = (p - 1) * (q - 1)

e = 0
for i in range(2, phi):
    if math.gcd(i, phi) == 1:
        e = i
        break

d = 0
for i in range(1, phi):
    if (e * i) % phi == 1:
        d = i
        break

print("\n========== RSA KEYS =================")
print("Public Key (e, n):", e, n)
print("Private Key (d, n):", d, n)
print("=====================================\n")

AES_KEY = bytes.fromhex("9F3A8C2E7D41B6A590DE2C7F8A134EBC6D2F0A9E5B47C81D3A6E94F2BC058710")

def generate_unique_code(length):
    while True:
        code = ''.join(random.choice(ascii_uppercase) for _ in range(length))
        if code not in rooms:
            return code

@app.route('/', methods=['GET', 'POST'])
def home():
    session.clear()
    if request.method == "POST":
        name = request.form.get("name")
        code = request.form.get("code")
        join = request.form.get("join", False)
        create = request.form.get("create", False)

        if not name:
            return render_template("home.html", error="Please enter a name", code=code, name=name)

        if not code and join != False:
            return render_template("home.html", error="Please enter a room code", code=code, name=name)

        room = code
        if create != False:
            room = generate_unique_code(4)
            rooms[room] = {"members": 0, "messages": []}
        elif code not in rooms:
            return render_template("home.html", error="Room does not exist", code=code, name=name)

        session["room"] = room
        session["name"] = name

        return redirect(url_for("room"))

    return render_template('home.html')

@app.route("/room")
def room():
    room = session.get("room")
    if room is None or session.get("name") is None or room not in rooms:
        return redirect(url_for("home"))
    return render_template("room.html", code=room, messages=rooms[room]["messages"])

@socketio.on("message")
def message(data):
    room = session.get("room")
    sender = session.get("name")

    if room not in rooms:
        return

    original_message = data["data"]

    print("\nMessage encryption:")
    print("Sender:", sender)
    print("Original Message:", original_message)

    # encrypt
    rsa_cipher = []
    for ch in original_message:
        encrypted = pow(ord(ch), e, n)
        rsa_cipher.append(str(encrypted))

    rsa_cipher_text = ",".join(rsa_cipher)
    print("RSA Encrypted:", rsa_cipher_text)

    cipher = AES.new(AES_KEY, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(rsa_cipher_text.encode(), AES.block_size))
    encrypted_text = base64.b64encode(cipher.iv + ciphertext).decode()

    print("AES Encrypted (Transmitted):", encrypted_text)

    # decrypt
    print("\nMessage decryption:")

    raw = base64.b64decode(encrypted_text)
    iv = raw[:16]
    actual_ciphertext = raw[16:]

    cipher_dec = AES.new(AES_KEY, AES.MODE_CBC, iv)
    decrypted_rsa_text = unpad(cipher_dec.decrypt(actual_ciphertext), AES.block_size).decode()
    print("AES Decrypted:", decrypted_rsa_text)

    decrypted_message = ""
    for c in decrypted_rsa_text.split(","):
        decrypted_char = pow(int(c), d, n)
        decrypted_message += chr(decrypted_char)

    print("RSA Decrypted:", decrypted_message)
    print("-------------------------------------------------------------------------------------------")

    socketio.emit(
        "message",
        {"name": sender, "message": decrypted_message},
        to=room
    )

@socketio.on("connect")
def connect(auth):
    room = session.get("room")
    name = session.get("name")
    if not room or not name:
        return

    join_room(room)
    rooms[room]["members"] += 1
    send({"name": name, "message": "has entered the room"}, to=room)

@socketio.on("disconnect")
def disconnect():
    room = session.get("room")
    name = session.get("name")
    leave_room(room)

    if room in rooms:
        rooms[room]["members"] -= 1
        if rooms[room]["members"] <= 0:
            del rooms[room]

    send({"name": name, "message": "has left the room"}, to=room)

if __name__ == '__main__':
    socketio.run(app, debug=True)