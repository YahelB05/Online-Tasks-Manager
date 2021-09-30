# Server Side:
import socket  # opens sockets (communications) between the server and clients
import select  # allows serving of multiple client in the same time
from online_tasks_manager_protocol import *  # imports all the constants and functions from the client-server protocol
import logging  # we'll be using log files to track changes
import sqlite3  # handles the databases
import hashlib  # hash password before adding them to the database
import uuid  # the server will generate session id's with the uuid.uuid4() method and store them in the user's database.
import time  # to know what time did the user add his task & to use time.sleep(10) for the DoS attack prevention section
import threading  # used to search DoS attacks (every 10 seconds search, asynchronous, for a potential attack)

# Configs:
logging.basicConfig(filename='online_task_tracker_changes.log', filemode='w', level=logging.INFO,
                    format='%(levelname)s:%(message)s')

# Global Variables:
MENU = """
1 - Add Task
2 - Remove Task
3 - Update Task
4 - Show Tasks
5 - Exit 
"""
# The one and only page - the menu page. when a client requests to get a page - this is the page that he will
# get if there are no errors.

CHECK_FOR_DOS_EVERY = 10  # checks for DoS attack every x seconds (x = CHECK_FOR_DOS_EVERY).
MAX_AMOUNT_OF_TASKS_SLOTS_FOR_USER = 5  # limits the amount of tasks each user can store.

# allows the transfer of ownership over the program between threads. Used in the thread to check for DoS attacks:
lock = threading.Lock()


class User:
    """
    Class that represents a new User in the 'Online Tasks Manager Command-Line Application'

    There are no setters because changing username and password is futile in such application -
    if the user wants, he can create a new user.
    """

    def __init__(self, username, password):
        """
		The constructor sets a username variable to the given username, and sets a password variable to the
		hashed version of the given password

		:param username: a valid username of the client.
		:param password: a valid password of the client.

		:type username: str
		:type password: str

		:returns: None
		"""

        self._username = username
        self._password = self.hash_data(password)

    @property
    def username(self):
        """
        Property to access the 'username' variable without being able to change the value.
        Acts as a standard Getter function, but without any need to call the function -
        when stating 'user_instance.username', it's like 'user_instance.get_username()'.
        """

        return self._username

    @property
    def password(self):
        """
        Property to access the 'password' variable without being able to change the value.
        Acts as a standard Getter function, but without any need to call the function -
        when stating 'user_instance.password', it's like 'user_instance.get_password()'.
        """

        return self._password

    @staticmethod
    def hash_data(data):
        """
		This staticmethod hashes the password within the class and also outside the class by calling 'User.hash_data()'.
		This function also hashed the session id's that are stored in the database - same as the passwords.
		The hashing algorithm is SHA-1.

		:param data: the data to be hashed.

		:type data: str

		:returns: the hashed version of the data.
		:rtype: str
		"""

        data = data.encode()
        hashed_data = hashlib.sha1(data).hexdigest()
        return hashed_data


# Setups Of The Server And The Database:
def setup_server():
    """
	Sets up the Online Tasks Manager server over TCP and IPv4 protocols.

	:returns: the server socket.
	:rtype: socket
	"""

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(SERVER)
    server.listen()

    print_and_log('server is up', logging.INFO)

    return server


def setup_database():
    """
	Sets up the online_tasks_tracker.db file that will contain 3 tables: users, tasks, banned_users.
	The function connects to the file (creates it if doesn't exist), and creates the 3 tables if they do not exist.

	:returns: the connection to the sqlite3 database and the cursor to it. the cursor allows altering of the database.
	:rtype: tuple
	"""

    # connection to the database, check_same_thread=False allows using the database's objects over multiple threads:
    conn = sqlite3.connect('online_tasks_tracker.db',
                           check_same_thread=False)
    cursor = conn.cursor()  # cursor allows the altering of the database

    # the passwords and session id's stored in the user's table are hashed with the SHA-1 algorithm (produces a fixed
    # length of 40 chars)
    cursor.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, \
													 username CHAR(20) NOT NULL, \
													 password CHAR(40) NOT NULL, \
													 session_id char(40) DEFAULT NULL)")

    cursor.execute("CREATE TABLE IF NOT EXISTS tasks(task_id INTEGER PRIMARY KEY, \
													 user_id INTEGER, \
													 task CHAR(100), \
													 time_of_addition CHAR(24), \
													 FOREIGN KEY(user_id) REFERENCES users(id))")

    cursor.execute("CREATE TABLE IF NOT EXISTS banned_users(ip_addr CHAR(15) UNIQUE, \
															user_id INTEGER)")

    conn.commit()  # saves changes
    print_and_log('database is up = users & tasks & banned_users tables', logging.INFO)

    return conn, cursor


# Functionalities Of The Server:
def trade_keys(conn_public_key, conn, clients_public_key, servers_public_key):
    """
    Trades the Server's and Client's Public Keys between each other.

    :param conn_public_key: a dict that stores the client's socket connection and the client's public key.
    :param conn: client's socket connection to the server.
    :param clients_public_key: client's public key.
    :param servers_public_key: server's public key.

    :type conn_public_key: dict
    :type conn: socket.connection
    :type clients_public_key: Crypto.PublicKey.RSA.RsaKey
    :type servers_public_key: Crypto.PublicKey.RSA.RsaKey

    :returns: updated dict of the client's socket connection and it's public key.
    :rtype: dict
    """

    conn_public_key[conn] = clients_public_key
    # There is no need to encrypt the server's public key because it'll take more time and it's not sensitive:
    send_msg(conn, CONNECTION_PROTOCOL['public key'], convert_key_to_str(servers_public_key))

    return conn_public_key


def login_user(database_conn_cursor, conn, username_password):
    """
	Takes care of logging in clients.

	:param database_conn_cursor: a tuple that consists of the connection to the database and the cursor to the database.
	:param conn: the client's connection to the server from the server-side.
	:param username_password: concatenated username and password with the delimiter ('|').

	:type database_conn_cursor: tuple
	:type conn: socket
	:type username_password: str

	:returns: if everything is valid and went well, it'll return tuple('200', new session id).
	          If not, tuple(bad status, '').
	:rtype: tuple
	"""

    username, password = split_username_password(username_password)  # splits the username and password via delimiter
    if not validate_username_password_server_side(username, password):  # checks if the data is valid:
        print_and_log(f'{conn.getpeername()[0]} gave invalid username or password', logging.WARNING)
        return '406', ''  # data given is invalid

    database_conn, database_cursor = database_conn_cursor

    if not user_exists(database_cursor, username, password):  # checks if the user exists, if not - give error msg:
        print_and_log(f'{conn.getpeername()[0]} tried to login with a non-existing user', logging.WARNING)
        return '407', ''  # user not found

    # check if user is banned (gotta check again in Login because attacker might have changed his IP address and then
    # logged into his account):
    database_cursor.execute("SELECT id FROM users WHERE username = ? AND password = ?",
                            (username, User.hash_data(password)))
    user_id = database_cursor.fetchone()[0]

    database_cursor.execute("SELECT 1 FROM banned_users WHERE user_id = ?", (user_id,))
    is_banned = database_cursor.fetchone()

    if is_banned:
        return '409', ''  # user is banned

    # now, the user is logged in for sure. He got the username and password correct.
    session_id = generate_sid()

    # sets a new session_id for the new client login:
    database_cursor.execute("UPDATE users SET session_id = ? WHERE username = ? AND password = ?", (
        User.hash_data(session_id), username, User.hash_data(password)))
    database_conn.commit()  # saves changes

    return '200', session_id


def signin_user(database_conn_cursor, conn, username_password):
    """
	Takes care of signing in clients.

	:param database_conn_cursor: a tuple that consists the connection to the database and the cursor to the database.
	:param conn: the client's connection to the server from the server-side.
	:param username_password: concatenated username and password with the delimiter ('|').

	:type database_conn_cursor: tuple
	:type conn: socket
	:type username_password: str

	:returns: if everything is valid and went well, it'll return tuple('200', new session id).
	          If not, tuple(bad status, '').
	:rtype: tuple
	"""

    username, password = split_username_password(username_password)  # splits the username and password via delimiter
    if not validate_username_password_server_side(username, password):  # checks if the data is valid:
        print_and_log(f'{conn.getpeername()[0]} gave invalid username or password', logging.WARNING)
        return '406', ''  # data given is invalid

    database_conn, database_cursor = database_conn_cursor

    if user_exists(database_cursor, username, password):  # checks if the user exists, if true - give error msg:
        print_and_log(f'{conn.getpeername()[0]} tried to sign in with an existing user', logging.WARNING)
        return '408', ''  # user already exists

    # now, the user is valid for sure. He got the username and password correct. Just need to create the user:
    user = User(username, password)  # User(username, hashed_password)
    session_id = generate_sid()

    # add user to the user's database:
    database_cursor.execute("INSERT INTO users(username, password, session_id) VALUES(?, ?, ?)",
                            (user.username, user.password, User.hash_data(session_id)))
    database_conn.commit()  # saves changes

    return '200', session_id


def add_new_task(database_conn_cursor, conn, data, users_session_id):
    """
	Adds a new task to the tasks table.

	:param database_conn_cursor: a tuple that consists the connection to the database and the cursor to the database.
	:param conn: the client's connection to the server from the server-side.
	:param data: the task that the client wants to add.
	:param users_session_id: the client's session id.

	:type database_conn_cursor: tuple
	:type conn: socket.connection
	:type data: str
	:type users_session_id: str

	:returns: the status of the operation, if the operation went well - it'll return '200', otherwise - a number
			  between 400-500.
	:rtype: str
    """

    if not validate_task_name(data):  # validates the task that the user wants to add
        return '405'  # task too long

    database_conn, database_cursor = database_conn_cursor

    # if the user changed the source code and got here without knowing a valid SID:
    if not session_id_exists(database_cursor, users_session_id):
        return '411'  # didn't login properly

    try:
        # find the user id by his session_id in order to know which task belongs to who (by inserting the user's id with
        # his task):
        database_cursor.execute("SELECT id FROM users WHERE session_id = ?", (users_session_id,))
        users_id = database_cursor.fetchone()[0]

        if out_of_task_slots(database_cursor, users_id):
            return '412'  # Used all x slots for saving his tasks.

        if is_out_of_tasks_space(database_cursor):
            return '414'  # tasks table is full

        # insert the user's task:
        current_time = time.asctime(time.localtime(time.time()))  # gets the time of the addition of the task
        database_cursor.execute("INSERT INTO tasks(user_id, task, time_of_addition) VALUES(?, ?, ?)",
                                (users_id, data, current_time))
        database_conn.commit()  # saves changes

    except sqlite3.Error:
        print_and_log(f'{conn.getpeername()[0]} - Failed to Add a Task', logging.INFO)
        return '400'

    else:
        print_and_log(f'{conn.getpeername()[0]} - Added a Task', logging.INFO)

    return '200'  # operation went well


def remove_task(database_conn_cursor, conn, data, users_session_id):
    """
	Removes a task of a certain user.

	:param database_conn_cursor: a tuple that consists the connection to the database and the cursor to the database.
	:param conn: the client's connection to the server from the server-side.
	:param data: the task that the client wants to remove.
	:param users_session_id: the client's session id.

	:type database_conn_cursor: tuple
	:type conn: socket.connection
	:type data: str
	:type users_session_id: str

	:returns: the status of the operation, if the operation went well - it'll return '200',
	          otherwise - a number between 400-500.
	:rtype: str
	"""

    database_conn, database_cursor = database_conn_cursor

    # if the user changed the source code and got here without knowing a valid SID:
    if not session_id_exists(database_cursor, users_session_id):
        return '411'  # didn't login properly

    # if the data given (task_id) is a number and belongs to the user with the given session_id then do:
    if data.isnumeric() and is_users_task(database_cursor, int(data), users_session_id):

        try:
            # if the task_id doesnt exist - it'll not do anything...
            # otherwise - it'll delete the row with the given task_id
            database_cursor.execute("DELETE FROM tasks WHERE task_id = ?", (int(data),))
            database_conn.commit()  # saves changes

        except sqlite3.Error:
            print_and_log(f'{conn.getpeername()[0]} - Failed to Removed a Task', logging.INFO)
            return '400'

        else:
            print_and_log(f'{conn.getpeername()[0]} - removed a task', logging.INFO)

        return '200'

    else:
        print_and_log(f'{conn.getpeername()[0]} - gave invalid data', logging.WARNING)
        return '406'  # data given is invalid


def update_task(database_conn_cursor, task_id_to_change, change_task_to):
    """
    Updates an already existing tasks of the user's.

    :param database_conn_cursor: a tuple that consists the connection to the database and the cursor to the database.
    :param task_id_to_change: the ID of the task that will be updated.
    :param change_task_to: the correction of the already existing task.

    :type database_conn_cursor: tuple
    :type task_id_to_change: int
    :type change_task_to: str

    :returns: the status of the operation, if the operation went well - it'll return '200', otherwise - a number
			  between 400-500.
    :rtype: str
    """

    database_conn, database_cursor = database_conn_cursor

    current_time = time.asctime(time.localtime(time.time()))  # gets the time of the update of the task
    try:
        database_cursor.execute("UPDATE tasks SET task = ? WHERE task_id = ?", (change_task_to, task_id_to_change))
        database_cursor.execute("UPDATE tasks SET time_of_addition = ? WHERE task_id = ?", (current_time,
                                                                                            task_id_to_change))
        database_conn.commit()  # saves changes
    except sqlite3.Error:
        return '400'
    else:
        return '200'


def show_users_tasks(database_cursor, session_id):
    """
	Shows all the tasks of a certain user in a nice format.

	:param database_cursor: database's cursor.
	:param session_id: the session id of the user that wants to see his tasks.

	:type database_cursor: sqlite3.cursor
	:type session_id: str

	:returns: the status of the operation, and the tasks of the user in a nice format.
	:rtype: tuple
	"""

    # if the user changed the source code and got here without knowing a valid SID:
    if not session_id_exists(database_cursor, session_id):
        return '411', ''  # didn't login properly

    formatted_data = ''
    tasks = users_tasks(database_cursor, session_id)

    for index, task in enumerate(tasks):
        formatted_data += ' | '.join(map(str, task))
        if index != len(tasks) - 1:
            formatted_data += '\n'

    return '200', formatted_data


def out_of_task_slots(database_cursor, user_id):
    """
    Checks if a certain user used all of their slots for storing tasks.

    :param database_cursor: database's cursor.
    :param user_id: user's id.

    :type database_cursor: sqlite3.cursor
    :type user_id: int

    :returns: returns True if the user is out of slots, otherwise - returns False.
    :rtype: bool
    """

    database_cursor.execute("SELECT count(*) FROM tasks WHERE user_id = ?", (user_id,))
    amount_of_tasks = database_cursor.fetchone()[0]

    if amount_of_tasks >= MAX_AMOUNT_OF_TASKS_SLOTS_FOR_USER:
        return True
    return False


def is_out_of_tasks_space(database_cursor):
    """
    Checks if the 'tasks' table is out of space for storing anymore records.

    :param database_cursor: database's cursor.

    :type database_cursor: sqlite3.cursor

    :returns: returns True if the table is out of space, otherwise - returns False
    :rtype: bool
    """

    database_cursor.execute("SELECT count(*) FROM tasks")
    records = database_cursor.fetchone()[0]

    if records >= MAX_AMOUNT_OF_TASKS_RECORDS:
        return True
    return False


def disconnect_client(client_conn, online_clients_list, database_conn_cursor, users_session_id, clients_public_key):
    """
	Disconnects the client from the server politely (if the user doesn't exit properly - it's a different situation).
	client: "Bye Server"  server: "Bye client" *hangs up*   client: *hangs up*

	:param client_conn: the client's connection to the server from server-side.
	:param online_clients_list: list of all online clients (open sockets with clients).
	:param database_conn_cursor: a tuple that consists the connection to the database and the cursor to the database.
	:param users_session_id: the session id of the user who wishes to disconnect.
    :param clients_public_key: client's public key.

	:type client_conn: socket
	:type online_clients_list: list
	:type database_conn_cursor: tuple
	:type users_session_id: str
    :type clients_public_key: Crypto.PublicKey.RSA.RsaKey

	:returns: the updated list of online clients (after removing the client who wanted to disconnect).
	:rtype: list
	"""

    # remove the client from the 'online_clients' list, let him know that he is about to be disconnected and then
    # disconnect him:
    online_clients_list.remove(client_conn)

    # reset the user's session_id in the database:
    database_conn, database_cursor = database_conn_cursor

    database_cursor.execute("UPDATE users SET session_id = ? WHERE session_id = ?", (None, users_session_id))
    database_conn.commit()  # saves changes

    send_encrypted_msg(client_conn, RESPONSE_PROTOCOL['status'], '200', clients_public_key)
    client_conn.close()

    return online_clients_list  # returns the updated list


# Helper Functions:
def print_and_log(msg, type_of_log):
    """
	Prints and logs into the .log file the given message. Used to track and document changes and actions.

	:param msg: the message that will be logged an printed.
	:param type_of_log: the type of log that the message will be (info, warning, error or critical).

	:type msg: str
	:type type_of_log: int

	:returns: None
	"""

    print(f'[{msg.upper()}]')

    if type_of_log is logging.INFO:
        logging.info(msg)
    elif type_of_log is logging.WARNING:
        logging.warning(msg)
    elif type_of_log is logging.ERROR:
        logging.error(msg)
    elif type_of_log is logging.CRITICAL:
        logging.critical(msg)


def give_page(database_cursor, session_id):
    """
	Returns the page that the user wanted.

	:param database_cursor: database's cursor.
	:param session_id: the session id of the user who wants the page.

	:type database_cursor: sqlite3.cursor
	:type session_id: str

	:returns: status of operation and the page (if was successful).
	:rtype: tuple
	"""

    if session_id_exists(database_cursor, session_id):
        return '200', MENU
    return '411', ''


def users_tasks(database_cursor, session_id):
    """
	Returns all the tasks that belong to the user with the given session id.

    Disclaimer: the 'user_id' field is not included!

	:param database_cursor: the cursor of the database, allows retrieving of data from the database.
	:param session_id: the session_id of the user, lets us know which tasks to get (of which user).

	:type database_cursor: sqlite3.cursor
	:type session_id: str

	:returns: a 2D list of all user's tasks.
	:rtype: list
	"""

    database_cursor.execute("SELECT tasks.task_id, tasks.task, tasks.time_of_addition \
                            FROM tasks WHERE user_id = (SELECT id FROM users WHERE session_id = ?)",
                            (session_id,))  # returns all the tasks of the user
    # equivalent query:
    # SELECT tasks.task_id, tasks.task, tasks.time_of_addition
    # FROM tasks
    # INNER JOIN users
    # ON tasks.user_id = users.id WHERE users.session_id = ?
    users_tasks_list = database_cursor.fetchall()  # all rows (tasks) that belong to the user with the given session id

    return users_tasks_list


def get_one_task(database_cursor, task_id, session_id):
    """
    Returns a certain task of the user's.
    This is used only when the user wants to update an existing task, and not just to view a certain task.

    Disclaimer: The user is able to modify the source code of the client side and get only one task.

    :param database_cursor: the cursor of the database, allows retrieving of data from the database.
    :param task_id: the ID of the task that the user wants to update.
	:param session_id: the session_id of the user, lets us know which tasks to get (of which user).

	:type database_cursor: sqlite3.cursor
	:type task_id: str
	:type session_id: str

	:returns: a tuple of a good status code with the one formatted wished task, or if something went wrong -
	          a bad status code with an empty placeholder.
	:rtype: tuple
    """

    if task_id.isnumeric() and is_users_task(database_cursor, int(task_id), session_id):

        try:
            database_cursor.execute("SELECT tasks.task FROM tasks WHERE user_id = \
                                    (SELECT id FROM users WHERE session_id = ?)", (session_id,))
        except sqlite3.Error:
            return '400', ''

        else:
            return '200', ''.join(database_cursor.fetchone())

    return '406', ''  # not the user's task


def split_username_password(username_password):
    """
	Splits the username and password from this format: username|password to this format: tuple(username, password).

	:param username_password: concatenated username and password with the delimiter ('|').

	:type username_password: str

	:returns: if the username and password given are valid, it'll return: tuple(username, password).
	          Otherwise, it'll return tuple(None, None).
	:rtype: tuple
	"""

    username_password_list = username_password.split(DELIMITER)
    if len(username_password_list) != 2:
        # meaning that the client put the '|' sign in the username or password, even though it's prohibited.
        # in order for the validate_username_password_server_side function to know that something is invalid:
        return None, None
    return tuple(username_password_list)


# Login Helper:
def track_login_requests(login_requests, conn, online_clients, clients_public_key):
    """
    Tracks client's login requests.
    If a client tries to login to many times - he'll get disconnected.

    :param login_requests: dict that stores the client's socket connection and the amount of login tries he tried.
    :param conn: client's socket connection to the server.
    :param online_clients: list of the current online clients.
    :param clients_public_key: client's public key.

    :type login_requests: dict
    :type conn: socket
    :type online_clients: list
    :type clients_public_key: Crypto.PublicKey.RSA.RsaKey

    :returns: a tuple of the updated dict of login requests & the updated list of online clients & bool value that
              indicates if a user was disconnected.
    :rtype: tuple
    """

    disconnected_client = False

    # count amount of logins every user tries:
    if conn in login_requests.keys():
        login_requests[conn] += 1
    else:
        login_requests[conn] = 1

    # checks if the user used all of his login tries - if so, disconnect him:
    if login_requests[conn] >= MAX_AMOUNT_OF_LOGIN_TRIES:
        print_and_log(f'{conn.getpeername()[0]} - Tried Too Many Logins', logging.INFO)

        del login_requests[conn]  # the user will be disconnected, no need to store that record anymore

        # sends the error msg to the client:
        send_encrypted_msg(conn, RESPONSE_PROTOCOL['status'], '413', clients_public_key)

        online_clients.remove(conn)
        conn.close()  # disconnects the client once and for all

        disconnected_client = True

    return login_requests, online_clients, disconnected_client


# Helpers for user-input validation:
def validate_username_password_server_side(username, password):
    """
	Validates the username and password from the server side this time,
	because the client might have changed the source code in his side.

	:param username: user's username.
	:param password: user's password.

	:type username: str
	:type password: str

	:returns: True if the username and password are valid, and False if not.
	:rtype: bool
	"""

    if validate_username_password(username, password) and username is not None:
        return True
    return False


def is_users_task(database_cursor, data, session_id):
    """
	Checks if the task id that the user entered belongs to him.

	:param database_cursor: the cursor of the database, will be passed as argument to the users_tasks function in order
	                        to get all the users tasks and check if one of them matches the given task id.
	:param data: the task id that the user entered.
	:param session_id: the session_id of the user, will be passed as argument to get the tasks of the user with the
	                   following session id.

	:type database_cursor: sqlite3.cursor
	:type data: int
	:type session_id: str

	:returns: True if it belongs to the user, and False if not.
	:rtype: bool
	"""

    database_cursor.execute("SELECT 1 FROM tasks WHERE user_id = (SELECT id FROM users WHERE session_id = ?) \
                             AND task_id = ?", (session_id, data))

    users_task = database_cursor.fetchone()

    if users_task:
        return True
    return False


# Helper for server's acceptation of clients:
def handle_new_client(server, database_cursor):
    """
	Accepts new clients to communicate with the server and checks if the IP that tries to establish a connection
	is banned or not (if it was a bigger application, i'd just block the IP address in the Firewall/Proxy configs!).

	:param server: the server's socket
	:param database_cursor: database's cursor

	:type server: socket.connection
	:type database_cursor: sqlite3.cursor

	:returns: tuple(True, client's socket) if the user IS banned, and tuple(False, client's socket) if not.
	:rtype: tuple
	"""

    client_sock, addr = server.accept()

    if check_if_banned_by_ip(database_cursor, addr[0]):
        print_and_log(f'{addr[0]}, a banned ip address, tried to connect to the server', logging.WARNING)
        return True, client_sock  # True = banned

    print_and_log(f'{addr[0]} connected to the server', logging.INFO)
    return False, client_sock  # False = not banned


# Helpers for getting unknown data by passing known data:
def get_user_id_by_session(database_cursor, session_id):
    """
	Returns the user's id by just knowing his session id.

	:param database_cursor: database's cursor.
	:param session_id: the session id of the user that we want to know his user id.

	:type database_cursor: sqlite3.cursor
	:type session_id: str

	:returns: the user id of the user with the given session id.
	:rtype: int
	"""

    database_cursor.execute("SELECT id FROM users WHERE session_id = ?", (session_id,))
    user_id = database_cursor.fetchone()[0]

    return user_id


# Helpers for the banning functionality:
def check_if_banned_by_ip(database_cursor, ip_addr):
    """
	Checks if the user's IP address is banned by seeing if it exists in the banned_users table.

	:param database_cursor: database's cursor.
	:param ip_addr: an IP address of a user who tries to login the system.

	:type database_cursor: sqlite3.cursor
	:type ip_addr: str

	:returns: True if is a banned ip address, False if not.
	:rtype: bool
	"""

    database_cursor.execute("SELECT 1 FROM banned_users WHERE ip_addr = ?", (ip_addr,))
    exists = database_cursor.fetchone()

    if exists:
        return True
    return False


def ban_user_id_ip(database_conn_cursor, attacker_id, attacker_ip):
    """
	Bans a user by his user id and IP address.

	:param database_conn_cursor: a tuple that consists the connection to the database and the cursor to the database.
	:param attacker_id: the user id of the attacker (user that will be banned).
	:param attacker_ip: the IP address of the attacker (user that will be banned).

	:type database_conn_cursor: tuple
	:type attacker_id: int
	:type attacker_ip: str

	:returns: None
	"""

    database_conn, database_cursor = database_conn_cursor

    database_cursor.execute("INSERT INTO banned_users VALUES(?, ?)", (attacker_ip, attacker_id))
    database_conn.commit()  # saves changes

    print_and_log(f'User ID: {attacker_id}, IP: {attacker_ip} was banned for DoS attacking', logging.INFO)


# Helper for authentication purposes:
def generate_sid():
    """
	Generates a random session id.

	:returns: random session id.
	:rtype: str
	"""

    # these session id's are stored in the 'users' database. when the user logins - the NULL value from that column
    # will change to a new session id. after every logout, the column switches to NULL again. uuid4 generates a total
    # random session id. uuid1 uses machine/sequence/time info to generate a UUID (not as secure as uuid4).
    return str(uuid.uuid4())


def session_id_exists(database_cursor, session_id):
    """
	Checks if such a session id in active and still in the database.

	:param database_cursor: database's cursor.
	:param session_id: the session id that we want to check if is active and in the database.

	:type database_cursor: sqlite3.cursor
	:type session_id: str

	:returns: True if exists, and False if not.
	:rtype: bool
	"""

    database_cursor.execute("SELECT 1 FROM users WHERE session_id = ?", (session_id,))
    exists = database_cursor.fetchone()

    if exists:
        return True
    return False


def user_exists(cursor, username, password):
    """
	Checks if the user exists in the users table inside of the database.

	:param cursor: the cursor to the database.
	:param username: user's username.
	:param password: user's password.

	:type cursor: sqlite3.cursor
	:type username: str
	:type password: str

	:returns: True if the user exists in the users table, and False if not.
	rtype: bool
	"""

    cursor.execute("SELECT 1 FROM users WHERE username = ? and password = ?",
                   (username, User.hash_data(password)))  # checks if the user exists
    exists = cursor.fetchone()

    if exists:
        return True
    return False


# Router to each functionality helper:
def handle_client_request(client_conn, cmd, data, session_id, online_clients_list, database, clients_public_key,
                          conn_task_to_update, login_requests, conn_public_key):
    """
	Handles client's request and gathers up all the helper functions.

	:param client_conn: the client's connection to the server from the server-side.
	:param cmd: the command that the client wants the server to do for him.
	:param data: the following data to the cmd.
	:param session_id: client's session_id.
	:param online_clients_list: the list of all online clients (all open sockets with clients at the moment).
	:param database: a tuple that contains the connection and cursor to the database.
    :param clients_public_key: client's public key.
    :param conn_task_to_update: dict that stores the client's socket and the task ID he wished to update while he
                                decides what to update it to.
    :param login_requests: dict that contains a client's socket and the amount of times he tried to login.
    :param conn_public_key: dict that contains a client's socket and his public key.

	:type client_conn: socket
	:type cmd: str
	:type data: str
	:type session_id: str
	:type online_clients_list: list
	:type database: tuple
    :type clients_public_key: Crypto.PublicKey.RSA.RsaKey
    :type conn_task_to_update: dict

	:returns: all the updated data structures that were given as an argument to this function.
	:rtype: tuple
	"""

    send_status = True
    status = '400'

    updated_online_clients_list = online_clients_list

    if cmd not in REQUEST_PROTOCOL.values():
        status = '404'  # cmd not found

    elif cmd == REQUEST_PROTOCOL['add']:
        status = add_new_task(database, client_conn, data, session_id)

    elif cmd == REQUEST_PROTOCOL['remove']:
        status = remove_task(database, client_conn, data, session_id)

    elif cmd == REQUEST_PROTOCOL['get one task']:
        status, one_task = get_one_task(database[1], data, session_id)
        # the one_task can be a task or a placeholder ('').

        if status == '200':
            conn_task_to_update[client_conn] = int(data)
            send_encrypted_msg(client_conn, RESPONSE_PROTOCOL['one task'], one_task, clients_public_key)
            send_status = False

    elif cmd == REQUEST_PROTOCOL['update']:
        status = update_task(database, conn_task_to_update[client_conn], data)

        if status == '200':  # means that there is no need to store the task to update - it was already done by now.
            del conn_task_to_update[client_conn]
            print_and_log(f"{client_conn.getpeername()[0]} - Updated a Task", logging.INFO)
        else:
            print_and_log(f"{client_conn.getpeername()[0]} - Failed to Update a Task", logging.INFO)

    elif cmd == REQUEST_PROTOCOL['disconnect']:
        updated_online_clients_list = disconnect_client(client_conn, online_clients_list, database, session_id,
                                                        clients_public_key)
        send_status = False

        if client_conn in conn_public_key.keys():
            del conn_public_key[client_conn]

    elif cmd == REQUEST_PROTOCOL['login']:
        status, session_id = login_user(database, client_conn, data)
        # the session_id might be '' because the status indicates an error. It's handled in the main() function.

        if status == '200':
            # if the user wanted to login & logged in successfully -> send him his session_id so he can
            # use the server.
            send_encrypted_msg(client_conn, RESPONSE_PROTOCOL['session id'], session_id, clients_public_key)
            send_status = False

            if client_conn in login_requests.keys():
                del login_requests[client_conn]  # he logged in within <= x requests, no need to store that record

        else:
            # tracks and handles amount of login / sign in requests:
            login_requests, online_clients, disconnected_client = track_login_requests(
                login_requests,
                client_conn,
                online_clients_list,
                conn_public_key[client_conn])

            if disconnected_client:
                send_status = False

    elif cmd == REQUEST_PROTOCOL['sign in']:
        status, session_id = signin_user(database, client_conn, data)
        # the session_id might be '' because the status indicates an error. It's handled in the main() function.

        if status == '200':
            # if the user wanted to login & logged in successfully -> send him his session_id so he can
            # use the server.
            send_encrypted_msg(client_conn, RESPONSE_PROTOCOL['session id'], session_id, clients_public_key)
            send_status = False

            if client_conn in login_requests.keys():
                del login_requests[client_conn]  # he logged in within <= x requests, no need to store that record

        else:
            # tracks and handles amount of login / sign in requests:
            login_requests, online_clients, disconnected_client = track_login_requests(
                login_requests,
                client_conn,
                online_clients_list,
                conn_public_key[client_conn])

            if disconnected_client:
                send_status = False

    elif cmd == REQUEST_PROTOCOL['show']:
        status, users_tasks_list = show_users_tasks(database[1], session_id)

        if status == '200':
            # if the user wants to view his tasks and the operation went well -> send the user his tasks:
            send_encrypted_msg(client_conn, RESPONSE_PROTOCOL['tasks'], users_tasks_list, clients_public_key)
            send_status = False

    elif cmd == REQUEST_PROTOCOL['get']:
        status, page = give_page(database[1], session_id)

        if status == '200':
            # if the user logged in properly -> send the user the main page, the menu:
            send_encrypted_msg(client_conn, RESPONSE_PROTOCOL['page'], page, clients_public_key)
            send_status = False

    if send_status:
        # if the user is already logged in/signed in and wants to add/remove OR tried to do an
        # operation but it failed - then just send him his error status back.
        # responds to the client with the adequate status number:
        send_encrypted_msg(client_conn, RESPONSE_PROTOCOL['status'], status, clients_public_key)

    return updated_online_clients_list, conn_task_to_update, login_requests, conn_public_key


def main():
    # setups of the server & database:
    server = setup_server()
    database_conn, database_cursor = setup_database()

    # setup for the Server's Encryption / Decryption Keys:
    public_key, private_key = handle_keys(Machine.S)

    # Requests and Clients:
    online_clients = []  # list of open sockets with client. (online clients sockets).
    last_x_seconds = []  # stores the ip's of the users who sent a request in the last CHECK_FOR_DOS_EVERY seconds.
    login_requests = {}  # used to keep track of the amount of tries the user tried to login (he should have x attempts)
    conn_public_key = {}  # stores the client's socket connection and his public key till the user logs in.
    conn_task_to_update = {}  # stores the client's socket and the task ID he wished to update while he decides

    # what to update it to

    def find_attack():
        """
		Thread function that searches every 10 seconds for a possible DoS attack that is being performed on the server.
		If it detects an attack, it bans the user by his ID and also bans his IP address.
		"""

        nonlocal last_x_seconds, online_clients

        while True:  # always keeps checking for attacks
            time.sleep(CHECK_FOR_DOS_EVERY)  # waits x (CHECK_FOR_DOS_EVERY variable) seconds till next check
            for id_conn in last_x_seconds:  # iterate over every request in the requests list of the last x seconds
                # if a single user requested and flooded the server with x*2 or more requests in the last x seconds -
                # it's an attack:
                if last_x_seconds.count(id_conn) >= CHECK_FOR_DOS_EVERY * 2:
                    print_and_log(f'{id_conn[1].getpeername()[0]} tried to DoS attack!', logging.WARNING)
                    online_clients.remove(id_conn[1])
                    try:
                        lock.acquire(True)  # takes ownership over the program for a moment in order to ban the user.
                        ban_user_id_ip((database_conn, database_cursor), id_conn[0],
                                       id_conn[1].getpeername()[0])  # adds him to banned_users database
                    finally:
                        lock.release()  # gives up the ownership over the program after banning the user.
                        id_conn[1].close()  # closes the connection with the attacker
                        last_x_seconds.clear()  # clears the list, so new requests can fill up for the next 10 seconds

    # when the code reaches here - every X seconds, there will be a check for an attack, even if no one is online... :
    # the following Thread is daemon, meaning that if the server terminates - the thread will also be:
    searching_dos_attacks = threading.Thread(target=find_attack, daemon=True)
    searching_dos_attacks.start()

    while True:
        ready_to_read, _, _ = select.select(online_clients + [server], [], [])

        for conn in ready_to_read:
            try:
                if conn is server:  # a client wants to connect to the server.

                    is_banned, new_client = handle_new_client(server, database_cursor)
                    if is_banned:  # means that a banned ip address tried to connect.
                        # the msg won't be encrypted because the keys weren't traded yet... :
                        send_msg(new_client, RESPONSE_PROTOCOL['status'], '410')  # 410 - banned IP
                        new_client.close()  # right after accepting the banned user, closing the connection.
                    else:  # means that the user is not banned, and we should connect him to the server properly.
                        online_clients.append(new_client)

                else:
                    # a client sends a request to the server, the server needs to receive the msg, process it,
                    # and respond.
                    packets = recv_msg(conn)  # encrypted and encoded packets that were received.

                    # decrypts and parses the msg as needed:
                    if conn in conn_public_key.keys():  # msg is encrypted and needs to be decrypted:
                        tuple_data = parse_msg(packets, private_key)
                    else:  # msg is NOT encrypted and DOESN'T need to be decrypted:
                        tuple_data = parse_msg(packets)

                    # the data is still unpacked because we need to check how many elements are there in the tuple:
                    if len(tuple_data) == 2:
                        cmd, data = tuple_data
                        session_id = ''  # default value
                    else:
                        cmd, data, session_id = tuple_data
                        # used to compare the hashed SIDs with the ones in the database:
                        session_id = User.hash_data(session_id)

                    # prints the corresponding message to the client's request:
                    if cmd == CONNECTION_PROTOCOL['public key']:
                        # informs that the server received a public key from a certain IP:
                        print_and_log(f'{conn.getpeername()[0]} - {cmd} - *public key*', logging.INFO)
                    elif cmd == REQUEST_PROTOCOL['login'] or cmd == REQUEST_PROTOCOL['sign in']:
                        # informs that the server received a login request from a certain IP and this is his username:
                        print_and_log(f'{conn.getpeername()[0]} - {cmd} - {split_username_password(data)[0]}',
                                      logging.INFO)
                    else:  # prints and logs Insensitive info that the user sent to the server:
                        print_and_log(f'{conn.getpeername()[0]} - {cmd} - {data}', logging.INFO)

                    # used to detect a DoS attack and handle it by banning the user (adding him to the banned_users
                    # database). every 10 requests, the system basically checks if a DoS attack Occurred:
                    if session_id and session_id_exists(database_cursor, session_id):
                        last_x_seconds.append((get_user_id_by_session(database_cursor, session_id), conn))
                    else:
                        last_x_seconds.append((None, conn))

                    # keeps serving the clients... :

                    # if it's the first interaction with the server - they need to first of all trade public keys:
                    if cmd == CONNECTION_PROTOCOL['public key']:
                        conn_public_key = trade_keys(conn_public_key, conn, convert_str_to_key(data), public_key)
                        continue

                    # if the code reached here, the client already traded keys with the server and he can transfer
                    # sensitive data over the sockets:
                    clients_public_key = conn_public_key[conn]  # gets the public key of the client by his socket conn

                    # handles the client's request securely:
                    handle_client_request(conn,
                                          cmd,
                                          data,
                                          session_id,
                                          online_clients,
                                          (database_conn, database_cursor),
                                          clients_public_key,
                                          conn_task_to_update,
                                          login_requests,
                                          conn_public_key)

            except (socket.error, KeyboardInterrupt, ConnectionResetError, struct.error, ValueError, KeyError) \
                    as error_msg:
                # the code reaches here only if the client closed the application by closing the tab/used ctrl+c
                # & changed the source code in the client-side with hope to take down the server...
                print_and_log(f'{conn.getpeername()[0]} - {error_msg}', logging.ERROR)

                # if the client is somehow in the following dicts - it'll make sure to remove him:
                if conn in conn_task_to_update.keys():
                    del conn_task_to_update[conn]

                if conn in login_requests.keys():
                    del login_requests[conn]

                if conn in conn_public_key.keys():
                    del conn_public_key[conn]

                # remove the client from the 'online_clients' list and disconnect him:
                online_clients.remove(conn)
                conn.close()  # disconnects the problematic client once and for all

            except Exception as error_msg:  # in case of failure - close everything properly without data loss:
                server.close()
                database_conn.close()
                print_and_log(f"Server is down! Error msg: {error_msg}", logging.CRITICAL)


if __name__ == '__main__':
    main()
