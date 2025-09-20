````markdown
# Encrypted Chat Terminal

This is a **terminal-based encrypted chat application** built using **Java, JLine, and SQLite**.  
The project implements end-to-end encryption, secure key management, and database support for user handling.

---

## Features
- End-to-End Encryption using AES
- Secure Key Management
- Terminal-based Chat Interface
- SQLite Database Integration
- Lightweight & Fast

---

## How to Run

1. **Clone the repository**
   ```bash
   git clone https://github.com/godfathershashank/Encrypted_Chat_Termial.git
   cd Encrypted_Chat_Termial
````

2. **Compile the code**

   ```bash
   javac -cp "lib/*;src" -d bin src/chat/*.java
   ```

3. **Start the server**

   ```bash
   java -cp "bin;lib/*" chat.ChatServer
   ```

4. **Start a client (open another terminal)**

   ```bash
   java -cp "bin;lib/*" chat.ChatClient YourName
   ```

---

## Bugs / Limitations

* No GUI (only terminal-based).
* Currently supports local connections only.
* Needs better error handling for edge cases.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Acknowledgement

This project was developed by **Shashank Singh Gautam**
as part of a his learning project at **ITM GIDA, Gorakhpur, India**. ![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/godfathershashank/Encrypted_Chat_Termial?utm_source=oss&utm_medium=github&utm_campaign=godfathershashank%2FEncrypted_Chat_Termial&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)
