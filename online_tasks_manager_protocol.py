# Client's & Server's Agreed Protocol:
import struct  # used to pack / unpack data that was / will be transferred over the sockets.

from Crypto.Cipher import PKCS1_OAEP  # used to encrypt / decrypt messages.
from Crypto.PublicKey import RSA  # used to generate RSA Asymmetric Keys.

import os  # used to check if the key's files exists & change the key file to 'readable only mode'.
import stat  # used to make the key file only readable.
import enum  # used to know if the machine is a server or a client.


class Machine(enum.Enum):
    """
    Useful to determent the name of the Private Key File in a way that if the Server and the Client run on the
    same Machine, it'll not cause any harm or conflict.
    """

    S = enum.auto()  # Server
    C = enum.auto()  # Client


REQUEST_PROTOCOL = {'add': '[ADD]',
                    'remove': '[RMV]',
                    'disconnect': '[DIS]',
                    'login': '[LGN]',
                    'sign in': '[SGN]',
                    'show': '[SHW]',
                    'get': '[GET]',
                    'get one task': '[G1T]',
                    'update': '[UPD]'}  # protocol that the client uses in order to send requests to the server.

RESPONSE_PROTOCOL = {'status': '[STS]',
                     'session id': '[SID]',
                     'tasks': '[TSK]',
                     'page': '[PAG]',
                     'one task': '[S1T]'}  # protocol that the server uses in order to send responses to the client.

CONNECTION_PROTOCOL = {'public key': '[PUB]'}  # protocol that the client and the server use to trade their public keys.

# used in the client side, it translates the status number that the server sends to human words:
STATUS_PROTOCOL = {'200': 'Task Completed Successfully!',
                   '400': 'Error Has Occurred... Please Try Again Later.',
                   '404': 'Command Not Found...',
                   '405': 'Task Too Long...',
                   '406': 'Data Given Is Invalid!',
                   '407': 'User Not Found...',
                   '408': 'User Already Exists!',
                   '409': 'User is banned!',
                   '410': 'Banned IP!',
                   '411': 'Didn\'t Login Properly!',
                   '412': 'Out Of Slots For Tasks. Used them all already!',
                   '413': 'Too Many Login Tries, Try Again Later...',
                   '414': 'The Database Is Full, Contact The Manager In Order To Address This Issue.'}

# Cross file configs:
SERVER = ('0.0.0.0', 8200)  # server's IP and listening port.
MAX_AMOUNT_OF_LOGIN_TRIES = 5  # limits the amount of logins every client can try.
MAX_AMOUNT_OF_TASKS_RECORDS = 999  # limits the amount of records in the 'tasks' table.

# Networking configs:
BIT_LENGTH_OF_KEY = 3072  # 1024 / 2048 / 3072
# the public key must be larger or equal to the msg it'll encrypt (bytes size):
MAX_PACKET_SIZE = int(BIT_LENGTH_OF_KEY / 8)
PEM_PUBLIC_KEY_LENGTH = 624  # length of the public key when it's in PEM format (the format it's sent over the sockets).

CMD_LEN = 5  # e.g: [ADD] = 5 chars
TASK_DESCRIPTION_LEN = len(str(MAX_AMOUNT_OF_TASKS_RECORDS)) + 100 + 24  # task id length, 100-task length, 24-date info
SID_LEN = 36  # a uuid4 session id consists of 36 chars

DELIMITER = '|'  # used to separate the username and password (username|password).

# Structs:
REQUEST_STRUCT = struct.Struct(f'{CMD_LEN}s100s{SID_LEN}s')
"""
CMD_LEN - task command length,
100s - length of task the user can add / id of task to remove / None,
36s - length of session id (this field might be empty for some requests).
"""

LOGIN_STRUCT = struct.Struct(f'{CMD_LEN}s41s')
"""
CMD_LEN - task command length,
20 bytes for name + 20 bytes for password + 1 byte for delimiter.
"""

RESPONSE_STRUCT = struct.Struct(f'{CMD_LEN}s{TASK_DESCRIPTION_LEN}s')
"""
CMD_LEN - task command length,
TASK_DESCRIPTION_LEN - user's task / session id / status / page.
"""

ALERT_PACKET_AMOUNT_STRUCT = struct.Struct('I')
""" Integer that represents the amount of packets to expect. """

KEY_TRADE_STRUCT = struct.Struct(f'{CMD_LEN}s{PEM_PUBLIC_KEY_LENGTH}s')
"""
CMD_LEN - task command length,
PEM_PUBLIC_KEY_LENGTH - byte size of the public key in PEM format.
"""

"""
EXAMPLES OF PACKETS:                                                                                  SENDER & RECEIVER:
[ADD]	'walk the dog at 5pm'                   'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF'                ~client -> server~
[RMV]	'3'                                     'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF'                ~client -> server~
[DIS]	''                                      'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF'                ~client -> server~
[LGN]	'asd|asd1234'                                                                                 ~client -> server~
[SGN]	'asd|asd1234'                                                                                 ~client -> server~
[SHW]	''										'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF'				  ~client -> server~
[GET]   ''                                      'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF'                ~client -> server~

[STS]	'200'                                                                                         ~server -> client~
[SID]   'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF'                                                        ~server -> client~
[TSK]	'1|walk the dog|Mon 2021'				  													  ~server -> client~
[PAG]   '1 - Add\n2 - Remove\n'                                                                       ~server -> client~

[PUB]   *large public key*                                                                           ~server <-> client~  
"""


# Security Of The Server and Client - Keys, Encryption and Decryption:
def generate_keys():
    """
    Generates a public key and a Private Key for the Server and Clients.
    The Public Key is used in order to encrypt, and the Private Key in order to decrypt the
    data transferred over the socket.
    Method Of Cryptography: Asymmetric Cryptography.

    :returns: public key and a private key
    :rtype: Crypto.PublicKey.RSA.RsaKey
    """

    private_key = RSA.generate(BIT_LENGTH_OF_KEY)
    public_key = private_key.publickey()  # public keys are generated from the private keys - they have a relation.

    return public_key, private_key


def convert_key_to_str(key):
    """
    Converts a Key Object to a string.

    :param key: the key object that will be converted to a string.

    :type key: Crypto.PublicKey.RSA.RsaKey

    :returns: the key in a string format
    :rtype: str
    """

    return key.export_key().decode('utf-8')


def convert_str_to_key(key_str):
    """
    Converts a string to a Key Object.

    :param key_str: a key in a string format.

    :type key_str: str

    :returns: the key in a Key Object format
    :rtype: Crypto.PublicKey.RSA.RsaKey
    """

    return RSA.import_key(key_str)


def keys_exists(public_key_file_name, private_key_file_name, folder_name):
    """
    Checks if the Public and Private Keys exist already in the key's folder
    in order to determent if there is a need to generate them.

    :param public_key_file_name: public key's file name
    :param private_key_file_name: private key's file name
    :param folder_name: the folder that the key files are stored in.

    :type public_key_file_name: str
    :type private_key_file_name: str
    :type folder_name: str

    :returns: True if the keys exist, otherwise - returns False.
    :rtype: bool
    """

    if os.path.exists(os.path.join(os.getcwd(), folder_name, public_key_file_name)) \
            and os.path.exists(os.path.join(os.getcwd(), folder_name, private_key_file_name)):
        return True
    return False


def folder_exists(folder_name):
    """
    Checks if the folder exists.

    :param folder_name: folder to check if exists.

    :type folder_name: str

    :returns: True if exists, otherwise - returns False.
    :rtype: bool
    """

    return os.path.exists(os.path.join(os.getcwd(), folder_name))


def save_keys_to_files(public_key, private_key, public_key_file_name, private_key_file_name, folder_name):
    """
    Saves the given Public and Private Keys to separate .pem file.

    :param public_key: the public key that will be stored in the .pem file.
    :param private_key: the private key that will be stored in the .pem file.
    :param public_key_file_name: public key's file name
    :param private_key_file_name: private key's file name
    :param folder_name: the folder that the key files are stored in.

    :type public_key: Crypto.PublicKey.RSA.RsaKey
    :type private_key: Crypto.PublicKey.RSA.RsaKey
    :type public_key_file_name: str
    :type private_key_file_name: str
    :type folder_name: str

    :returns: None
    """

    with open(os.path.join(os.getcwd(), folder_name, public_key_file_name), 'w') as key_file:
        key_file.write(convert_key_to_str(public_key))

    with open(os.path.join(os.getcwd(), folder_name, private_key_file_name), 'w') as key_file:
        key_file.write(convert_key_to_str(private_key))

    # makes the file just readable (unchangeable):
    os.chmod(os.path.join(os.getcwd(), folder_name, public_key_file_name), stat.S_IREAD)
    os.chmod(os.path.join(os.getcwd(), folder_name, private_key_file_name), stat.S_IREAD)


def extract_keys_from_files(public_key_file_name, private_key_file_name, folder_name):
    """
    Extracts / Imports the Public and Private Keys from the .pem file.

    :param public_key_file_name: public key's file name
    :param private_key_file_name: private key's file name
    :param folder_name: the folder that the key files are stored in.

    :type public_key_file_name: str
    :type private_key_file_name: str
    :type folder_name: str

    :returns: a tuple that consists of the Public and the Private Keys.
    :rtype: tuple
    """

    with open(os.path.join(os.getcwd(), folder_name, public_key_file_name), 'r') as key_file:
        public_key = convert_str_to_key(key_file.read())

    with open(os.path.join(os.getcwd(), folder_name, private_key_file_name), 'r') as key_file:
        private_key = convert_str_to_key(key_file.read())

    return public_key, private_key


def handle_keys(machine):
    """
    Handles the Generation, Exportation and Importation of the Private and Public Keys.

    :param machine: must be either Machine.S or Machine.C in order to name the Private Key file properly.
                    Important when running both client and server on the same machine!
    :type machine: Machine

    :returns: a tuple that consists of the Public and the Private Keys.
    :rtype: tuple
    """

    # finds valid key file names:
    if machine == Machine.S:
        public_key_file_name = 'servers_online_tasks_manager_public_key.pem'
        private_key_file_name = 'servers_online_tasks_manager_private_key.pem'
    elif machine == Machine.C:
        public_key_file_name = 'online_tasks_manager_public_key.pem'
        private_key_file_name = 'online_tasks_manager_private_key.pem'
    else:
        public_key_file_name = 'unknown_machine_online_tasks_manager_public_key.pem'
        private_key_file_name = 'unknown_machine_online_tasks_manager_private_key.pem'

    folder_name = 'keys'

    if keys_exists(public_key_file_name, private_key_file_name, folder_name):
        return extract_keys_from_files(public_key_file_name, private_key_file_name, folder_name)
    else:
        if not folder_exists(folder_name):
            os.mkdir(folder_name)

        public_key, private_key = generate_keys()
        save_keys_to_files(public_key, private_key, public_key_file_name, private_key_file_name, folder_name)

        return public_key, private_key


def encrypt_msg(msg, others_public_key):
    """
    Encrypts the given message using the public key of the machine you are sending the message to.
    Method Of Cryptography: Asymmetric Cryptography.

    :param msg: the message that will be encrypted.
    :param others_public_key: the public key of the machine that the message is being sent to.

    :type msg: bytes
    :type others_public_key: Crypto.PublicKey.RSA.RsaKey

    :returns: the encrypted message in bytes format
    :rtype: bytes
    """

    encryptor = PKCS1_OAEP.new(key=others_public_key)
    encrypted_msg = encryptor.encrypt(msg)

    return encrypted_msg


def decrypt_msg(encrypted_msg, my_private_key):
    """
    Decrypts the given message using the private key of the machine that called this function.
    Method Of Cryptography: Asymmetric Cryptography.

    :param encrypted_msg: the encrypted message that will be decrypted.
    :param my_private_key: the private key of the machine that calls this function, the only key that can decrypt this.

    :type encrypted_msg: bytes
    :type my_private_key: Crypto.PublicKey.RSA.RsaKey

    :returns: the decrypted message
    :rtype: bytes
    """

    decrypter = PKCS1_OAEP.new(key=my_private_key)
    decrypted_msg = decrypter.decrypt(encrypted_msg)

    return decrypted_msg


# Validation of the user-input:
def validate_task_name(task_name):
    """
    Validates the task that the client wants to add. Being validated both in client & server side.
    
    :param task_name: the task that the client wants to add.
    :type task_name: str
    
    :returns: True if is valid, and False if not.
    :rtype: bool
    """

    if len(task_name) <= TASK_DESCRIPTION_LEN:
        return True
    return False


def validate_username_password(username, password):
    """
    Validates the username and password that the client entered. Being validated both in client & server side.
    
    :param username: the username that the client entered.
    :param password: the password that the client entered.
    
    :type username: str
    :type password: str
    
    :returns: True if is valid, and False if not.
    :rtype: bool
    """

    if len(username) < 21 and len(password) < 21 and '|' not in username and '|' not in password:
        return True
    return False


# Building and Parsing messages:
def build_msg(task, data, session_id=''):
    """
    Builds the message that will be sent over sockets from client to server and vice versa.
    The message is being packed with a certain format, can be seen in the global variables of the file.
    
    :param task: the command that the client/server wants to send to the server/client.
    :param data: the following data that the client/server wants to send to the server/client with the command.
    :param session_id: the session_id of the client. Only being used from client-side & only in actions where the user
                       is already logged in. If not used, the default value is ''.

    :type task: str
    :type data: str
    :type session_id: str
    
    :returns: the packed & encoded message.
    :rtype: bytes
    """

    if task == CONNECTION_PROTOCOL['public key']:
        return KEY_TRADE_STRUCT.pack(bytes(task, 'utf-8'), bytes(data, 'utf-8'))
    elif task == REQUEST_PROTOCOL['login'] or task == REQUEST_PROTOCOL['sign in']:
        return LOGIN_STRUCT.pack(bytes(task, 'utf-8'), bytes(data, 'utf-8'))
    elif task in REQUEST_PROTOCOL.values():
        return REQUEST_STRUCT.pack(bytes(task, 'utf-8'), bytes(data, 'utf-8'), bytes(session_id, 'utf-8'))
    else:  # elif task in RESPONSE_PROTOCOL.values():
        return RESPONSE_STRUCT.pack(bytes(task, 'utf-8'), bytes(data, 'utf-8'))


def parse_msg(packets, my_private_key=None):
    """
    The opposite of the build_msg function, it parses the packed, encoded and maybe encrypted message to
    an unpacked, decoded and decrypted message.
    The message is being unpacked with a certain format, the same format the the message was packed with.
    
    :param packets: the encoded packets.
    :param my_private_key: the machine's private key that decrypts the msg, only if the msg is encrypted.

    :type packets: list
    :type my_private_key: Crypto.PublicKey.RSA.RsaKey

    :returns: a tuple of the unpacked data splitted into parts. (cmd, status, session_id='')
    :rtype: tuple
    """

    parsed_data = []

    if my_private_key is not None:  # means that the msg is encrypted:
        # decrypts and joins every packet in order for the structs to struct it well:
        msg = b''.join(map(lambda packet: decrypt_msg(packet, my_private_key), packets))
        cmd = msg[:CMD_LEN].decode('utf-8')  # first 5 bytes are the cmd
    else:  # means that the msg is not encrypted:
        # joins the encoded packets to one big packet:
        msg = b''.join(packets)
        cmd = msg[:CMD_LEN].decode('utf-8')  # more efficient than doing: msg.decode('utf-8')[:CMD_LEN]

    if cmd == CONNECTION_PROTOCOL['public key']:
        unpacked = KEY_TRADE_STRUCT.unpack(msg)
    elif cmd == REQUEST_PROTOCOL['login'] or cmd == REQUEST_PROTOCOL['sign in']:
        unpacked = LOGIN_STRUCT.unpack(msg)
    elif cmd in REQUEST_PROTOCOL.values():
        unpacked = REQUEST_STRUCT.unpack(msg)
    else:
        unpacked = RESPONSE_STRUCT.unpack(msg)

    for part in unpacked:  # removes excess bytes from data:
        parsed_data.append((part.split(b'\0', 1)[0]).decode('utf-8'))
    return tuple(parsed_data)  # (cmd, data, session_id = '' or a genuine session_id)


# Transportation of the messages from the client to the server, and vice versa:
def send_msg(conn, task, data, session_id=''):
    """
    Sending a message from the client/server to the server/client with the given parameters.
    
    :param conn: the connection of the client to the server from the client-side or from the server-side.
    :param task: the command that tells the server/client information of the following data.
    :param data: can be status/session id/user's tasks etc...
    :param session_id: the session_id of the client. Only being used from client-side & only in actions where the user
                       is already logged in. If not used, the default value is ''.
    
    :type conn: socket.connection
    :type task: str
    :type data: str
    :type session_id: str
    
    :returns: None
    """

    segments = segment_packet(build_msg(task, data, session_id))  # segments the large packet
    alert_packet_amount(conn, len(segments))  # alerts the other side of the socket the amount of packets to expect

    for segment in segments:  # sends each segment:
        conn.sendall(segment)


def send_encrypted_msg(conn, task, data, others_public_key, session_id=''):
    """
    Sends an encrypted version of the message with an Asymmetric Encryption.

    :param conn: the connection of the client to the server from the client-side or from the server-side.
    :param task: the command that tells the server/client information of the following data.
    :param data: can be status/session id/user's tasks.
    :param others_public_key: the public key of the other side of the connection, the msg will be encrypted using that.
    :param session_id: the session_id of the client. Only being used from client-side & only in actions where the user
                       is already logged in. If not used, the default value is ''.

    :type conn: socket.connection
    :type task: str
    :type data: str
    :type others_public_key: Crypto.PublicKey.RSA.RsaKey
    :type session_id: str

    :returns: None
    """

    segments = segment_packet(build_msg(task, data, session_id))  # segments the large packet
    segments = list(map(lambda s: encrypt_msg(s, others_public_key), segments))  # encrypts each segment

    alert_packet_amount(conn, len(segments))  # alerts the other side of the socket the amount of packets to expect

    for segment in segments:  # sends each segment:
        conn.sendall(segment)


def recv_msg(conn):
    """
    Receives a message from the server/client that was sent from the client/server.
    
    :param conn: the connection of the client to the server from the client-side or from the server-side.

    :type conn: socket.connection
    
    :returns: the encoded packets that were received.
    :rtype: list
    """

    packets_to_expect = recv_packet_alert(conn)

    segments = []  # stores the encrypted and encoded packets
    for _ in range(packets_to_expect):
        segments.append(conn.recv(MAX_PACKET_SIZE))

    return segments


# Alert Of Packets to Expect:
def alert_packet_amount(conn, packets):
    """
    Alerts the other end of the socket connection how many packets should he expect to receive.

    :param conn: the socket connection from the side that sends the alert.
    :param packets: the amount of packets that the other side of the socket connection should expect.

    :type conn: socket.connection
    :type packets: int

    :returns: None
    """

    conn.sendall(ALERT_PACKET_AMOUNT_STRUCT.pack(packets))


def recv_packet_alert(conn):
    """
    Receives the alert that lets us know how many packets to expect.

    :param conn: the socket connection from the side that receives the alert.

    :type conn: socket.connection

    :returns: the unpacked-decoded number of packets to expect.
    :rtype: int
    """

    return ALERT_PACKET_AMOUNT_STRUCT.unpack(conn.recv(ALERT_PACKET_AMOUNT_STRUCT.size))[0]


# Segmentation:
def segment_packet(packet):
    """
    Segments a large packet into multiple smaller packets that will be sent encrypted via sockets.

    :param packet: the packet that will be segmented if needed.

    :type packet: bytes

    :returns: a list that contains the segments of the large packet.
    :rtype: list
    """

    segmented_packets = []
    if len(packet) <= MAX_PACKET_SIZE:
        return [packet]

    start = 0
    end = MAX_PACKET_SIZE
    while end <= len(packet) + 1:
        segmented_packets.append(packet[start:end])
        start = end
        end += MAX_PACKET_SIZE

    if end - MAX_PACKET_SIZE < len(packet):
        segmented_packets.append(packet[end - MAX_PACKET_SIZE:])

    return segmented_packets  # the list is used to store the packets and to know how many packets are there to send.
