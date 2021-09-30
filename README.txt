# Table Of Contents
* [Project](#project)
* [Elements Applied on The Project](#elements-applied-on-the-project)
  * [Security and Network](#security-and-network)
  * [Server](#server)
  * [Client](#client)
  * [Etc...](#etc)
* [Disclamers](#disclamers)
* [Possible Improvements](#possible-improvements-to-apply-on-future-and-larger-projects)
* [Remote Server Setup](#remote-server-setup)
* [Installation](#installation)

# Project
This project provides an **Online Tasks Manager** that any registered client can log into the server, save the desired task, view it anytime, update it and remove it if so wished.\
Every user's saved tasks are private - just for him to see.

**The project was made to practice and implement a variety of programming, cryptography, security, and managing concepts.**

The main concept that I implemented is a similar connection between the server and the client such as SSH and SCP, just from basic Sockets and RSA Keys.
I implemented more concepts that will be mentioned in the following sections.

# Elements Applied on The Project
## Security and Network
- Asymmetric Cryptography Connection
- Partially DoS/DDoS Detection
- Password and Session ID Hashing
- Unchangeable Keys
- User input Verification both in Client and Server Side
- TCP Sockets and Structured Packets
- Packet Segmentation

## Server
- Relational Database with SQLite3
- Supplies accurate and adequate error and status responses to the clients
- Well organized Login and Logout System with an ability to ban attackers

## Client
- Least amount of code and data exposed to the client
- Simple and easy to understand CLI (Command Line Interface)
- Well Explained Error Codes

## Etc...
- Shared Client-Server Protocol File
- Well documented code using 'docstring'
- Modifiable code, by changing constants in the protocol and server files
- Logging and tracking data with a .log file in server-side

# Disclamers
- **This project does not support a fully secure connection!** Although an Asymmetric Cryptography Algorithm is applied, there is no Digital Signature System that will ensure the authenticity of the data.
- The server conducts a DoS/DDoS attack detection, but is not as reliable as it can be! The attacker will be banned by his IP Address and his User - Not by Proxy/Firewall Block!
- If a client modifies the source code of the client-side code, it **shouldn't** affect the server.
- The server does not validate the structure of the public key that the client supplied the server with.
- There is no option to change the username or password.
- The Hashing Algorithm used is SHA-1, easy to crack and exploit!

  **If a major penetration is being found - please report it to me via the 'Issues' section.**

# Possible Improvements to Apply on Future and Larger Projects
- Use MySQL instead of SQLite3
- Use Digital Signatures in case of transferring sensitive data (Slows Performance)
- Use a more secure Hashing Algorithm (Slows Performance)
- Block users by Firewall/Proxy
- Use Hybrid Cryptography
- Use premade Connection Establishers Libraries (e.g Paramiko) instead of implementing one
- Have an option to change the username and password
- Salt the passwords

# Remote Server Setup
**If running the Server on a separate machine from the Client:**
- make sure to change the server's IP in the client file to the machine's IP where the server runs.
The variable to be changed is at the top of the file.
In such a case, Change:
    ```diff
    - SERVER_ADDR = ('127.0.0.1', SERVER[1])
    + SERVER_ADDR = (remote_server_ip, corresponding_port)
    ```
- Setup proper Port Forwarding.

# Installation
- Use [git](https://git-scm.com/) to clone the repository:
    ```bash
    git clone https://github.com/YahelB05/online-tasks-manager/
    ```
    
- Change directory:
    ```bash
    cd online-tasks-manager/
    ```
    
- Use the package manager ['pip'](https://pip.pypa.io/en/stable/) to install the required modules:
    ```bash
    pip3 install -r requirements.txt
    ```
    
- Use [Python](https://www.python.org/) to run the server by typing:
    ```bash
    python online_tasks_manager_server.py
    ```
    
- Then move to another terminal and run the client by typing:
    ```bash
    python online_tasks_manager_client.py
    ```