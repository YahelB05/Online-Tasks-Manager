# Client Side:
import socket  # opens a socket between this machine (client) to the wished server.
from online_tasks_manager_protocol import *  # imports all the constants and functions from the client-server protocol
import getpass  # used to take the user's password in a secure & invisible way in the terminal.

SERVER_ADDR = ('127.0.0.1', SERVER[1])  # TODO: Change the IP when using a proper server!


# used only in client side because the server receives and then sends, but the client sends and only then receives:
def send_recv_msg(conn, task, data, session_id, servers_public_key=None, my_private_key=''):
    """
	Sends a command, following data corresponding to the command, and the user's session id in order for the server to
	recognize the client.
	Function also receives the server's response to the client's request and returns the command and
	status/session id/user's tasks according to the user's request.

	:param conn: the client's connection to the server via a socket.
	:param task: the command(task) that the user wants the server to do.
	:param data: the following data to the command.
	:param session_id: client's session id.
	:param servers_public_key: used to encrypt the data so only the server can decrypt it.
	:param my_private_key: client's private key that is used to decrypt the message that the server sent.

	:type conn: socket.connection
	:type task: str
	:type data: str
	:type session_id: str
	:type servers_public_key: Crypto.PublicKey.RSA.RsaKey
	:type my_private_key: Crypto.PublicKey.RSA.RsaKey

	:returns: server's command and following data.
	:rtype: tuple
	"""

    if servers_public_key is not None:
        send_encrypted_msg(conn, task, data, servers_public_key, session_id)
    else:
        send_msg(conn, task, data, session_id)

    packets = recv_msg(conn)

    # status might be the session id that the server assigns to the client / the user's tasks / just a status (good or
    # bad).
    if task == CONNECTION_PROTOCOL['public key']:
        cmd, status = parse_msg(packets)
    else:
        cmd, status = parse_msg(packets, my_private_key)

    return cmd, status


def validate_task_num(task):
    """
	Validates if the user entered a valid command that the server can do for him.
	1 - Add Task
	2 - Remove Task
	3 - Update Task
	3 - Show Tasks
	4 - Exit

	:param task: a number that SHOULD be from 1-4 that corresponds with a command to do.

	:type task: str

	:returns: True if the task number is valid, and False if it's not.
	:rtype: bool
	"""

    if task in ['1', '2', '3', '4', '5']:
        return True
    return False


def setup():
    """
	Sets up the connection between the client and the server via sockets.

	:returns: client-side connection to the server.
	:rtype: socket
	"""

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(SERVER_ADDR)

    return client


def disconnect(conn, session_id, servers_public_key, my_private_key):
    """
	Disconnects the client from the server by sending the server a request to disconnect him politely and if the server
	disconnected the client from his side - only then the client would too.

	:param conn: client's connection with the server.
	:param session_id: client's session id, it's necessary in order for the server to know which client to disconnect
					   and reset his session id till next time.
	:param servers_public_key: used to encrypt the data so only the server can decrypt it.
	:param my_private_key: client's private key that is used to decrypt the message that the server sent.

	:type conn: socket
	:type session_id: str
	:type servers_public_key: Crypto.PublicKey.RSA.RsaKey
	:type my_private_key: Crypto.PublicKey.RSA.RsaKey

	:returns: None
	"""

    # protocol (client_conn, [disconnect], default param, session_id)
    cmd, status = send_recv_msg(conn, REQUEST_PROTOCOL['disconnect'], '', session_id, servers_public_key,
                                my_private_key)

    if check_status(status):
        conn.close()

    print('Bye Bye :)')
    exit()


def check_status(status):
    """
	Receives a status ('200', '400' etc...) and translates it into words that tell if the status represents something
	good or not.
	After printing the status in human words, it also returns True if the status is fine, and returns False if not.

	:param status: number that represents a status - good or bad.

	:type status: str

	:returns: True if the status is good, and False if not.
	:rtype: bool
	"""

    print(STATUS_PROTOCOL[status])
    if int(status) >= 400:
        return False
    return True


def do_task(client, task, session_id, servers_public_key, my_private_key):
    """
	This function gets the client's request and performs it behind the scenes.

	:param client: the client's connection to the server.
	:param task: command ('1', '2', '3', '4') that the client wishes to perform.
	:param session_id: the client's session id, so the server knows on which user to perform the command on.
	:param servers_public_key: used to encrypt the data so only the server can decrypt it.
	:param my_private_key: client's private key that is used to decrypt the message that the server sent.

	:type client: socket
	:type task: str
	:type session_id: str
	:type servers_public_key: Crypto.PublicKey.RSA.RsaKey
	:type my_private_key: Crypto.PublicKey.RSA.RsaKey

	:returns: None
	"""

    if task == '1':  # add a task

        try:
            data_to_add = input('> Task: ')
        except (KeyboardInterrupt, ConnectionResetError):
            data_to_add = ''  # doesn't matter, there is an exit() function later to terminate the program anyways.
            disconnect(client, session_id, servers_public_key, my_private_key)

        if validate_task_name(data_to_add):
            # protocol ([add], task to add, session_id)
            cmd, status = send_recv_msg(client, REQUEST_PROTOCOL['add'], data_to_add,
                                        session_id, servers_public_key, my_private_key)
            check_status(status)

    elif task == '2':  # remove a task

        try:
            data_to_remove = input('> Task ID of the Task to Remove: ')
        except (KeyboardInterrupt, ConnectionResetError):
            data_to_remove = ''  # doesn't matter, there is an exit() function later to terminate the program anyways.
            disconnect(client, session_id, servers_public_key, my_private_key)

        if validate_task_name(data_to_remove):
            # protocol ([remove], task id to remove, session_id)
            cmd, status = send_recv_msg(client, REQUEST_PROTOCOL['remove'], data_to_remove, session_id,
                                        servers_public_key, my_private_key)
            check_status(status)

    elif task == '3':  # update a task
        task_id_to_update = input('> Task ID To Update: ')
        cmd, data = send_recv_msg(client, REQUEST_PROTOCOL['get one task'], task_id_to_update, session_id,
                                  servers_public_key, my_private_key)

        if cmd == RESPONSE_PROTOCOL['one task']:
            print('Your Task:')
            print(data)

            update_to = input('Update To: ')
            cmd, data = send_recv_msg(client, REQUEST_PROTOCOL['update'], update_to, session_id, servers_public_key,
                                      my_private_key)

            check_status(data)
        else:
            check_status(data)

    elif task == '4':  # show my tasks
        # protocol ([show], '', session_id)
        cmd, data = send_recv_msg(client, REQUEST_PROTOCOL['show'], '', session_id, servers_public_key, my_private_key)

        if cmd == RESPONSE_PROTOCOL['status']:
            check_status(data)
        elif cmd == RESPONSE_PROTOCOL['tasks']:
            print('Your Tasks:\n\nID:\tTASK:\tDATE:\n---------------------')
            print(data)
    else:  # disconnect
        # gets here only if the user pressed 4 (4 - exit), or pressed something invalid AND changed the source code on
        # his local machine.
        disconnect(client, session_id, servers_public_key, my_private_key)


def get_username_password(login_or_signin):
    """
	Asks for the client to enter his username and password till it's valid.

    :param login_or_signin: if it's '1' (login) - it'll ask the user to enter his password once,
    but if it's '2' (sign in) - it'll ask the user to confirm his password.

    :type login_or_signin: str

	:returns: a valid username and password. (assuming that the client didn't change the source code on his
			  local machine, he might have changed the validation system).
	:rtype: tuple
	"""

    try:
        username = input('> Username (20 chars max, no  "|"): ')
        password = getpass.getpass('> Password (20 chars max, no "|"): ')

        if login_or_signin == '2':  # for the own good of the client - makes sure he typed it correct:
            password_confirmation = getpass.getpass('> Confirm Password: ')
        else:
            password_confirmation = password

        while not validate_username_password(username, password) or not password == password_confirmation:
            print('Invalid Username or Password, Try Again...')

            username = input('> Username (20 chars max, no  "|"): ')
            password = getpass.getpass('> Password (20 chars max, no  "|"): ')

            if login_or_signin == '2':
                password_confirmation = getpass.getpass('> Confirm Password: ')

    except (KeyboardInterrupt, ConnectionResetError):
        username, password = '', ''  # doesn't matter, there is an exit() later to terminate the program anyways.
        print('Bye Bye :)')
        exit()

    return username, password


def concat_username_password(username, password):
    """
	Concatenates the username and password with a delimiter: '|'. It's needed in order to transfer the
	username and password in one part of the struct.

	:param username: client's username.
	:param password: client's password.

	:type username: str
	:type password: str

	:returns: concatenated username and password using a delimiter (username|password).
	:rtype: str
	"""

    return username + DELIMITER + password


def trade_keys(conn, my_public_key):
    """
	Trades Public Keys with the Server.
	The Client sends over his Public Key and the Server sends his Public Key in response if everything went well.

	:param conn: client's connection to the server.
	:param my_public_key: client's public key that will be sent over to the server.

	:type conn: socket.connection
	:type my_public_key: Crypto.PublicKey.RSA.RsaKey

	:returns: the public key of the server or nothing because of the exit().
	:rtype: Crypto.PublicKey.RSA.RsaKey
	"""

    #  sends the server the client's public_key:
    cmd, status = send_recv_msg(conn, CONNECTION_PROTOCOL['public key'], convert_key_to_str(my_public_key), '')
    # if everything went well, the status contains the server's public key.

    if cmd != CONNECTION_PROTOCOL['public key']:
        check_status(status)  # will return False and print the error message
        exit()

    return convert_str_to_key(status)  # returns the server's public key


def login(conn, username, password, servers_public_key, my_private_key):
    """
	Tries to login the client with the given username and password.

	:param conn: client's connection to the server.
	:param username: the client's entered username.
	:param password: the client's entered password.
	:param servers_public_key: used to encrypt the data so only the server can decrypt it.
	:param my_private_key: client's private key that is used to decrypt the message that the server sent.

	:type conn: socket.connection
	:type username: str
	:type password: str
	:type servers_public_key: Crypto.PublicKey.RSA.RsaKey
	:type my_private_key: Crypto.PublicKey.RSA.RsaKey

	:returns: the response command of the server and the following data (can be a bad status and can also be a
			  session id if the login went fine).
	:rtype: tuple
	"""

    cmd, status = send_recv_msg(conn, REQUEST_PROTOCOL['login'],
                                concat_username_password(username, password), '', servers_public_key, my_private_key)
    # I placed a placeholder ('') as the session id because the user still doesn't have one, he does this request to
    # get one...

    return cmd, status  # might not actually a status.. it might be a session id


def sign_in(conn, username, password, servers_public_key, my_private_key):
    """
	Tries to sign in the client with the given username and password.

	:param conn: client's connection to the server.
	:param username: the client's entered username.
	:param password: the client's entered password.
	:param servers_public_key: used to encrypt the data so only the server can decrypt it.
	:param my_private_key: client's private key that is used to decrypt the message that the server sent.

	:type conn: socket.connection
	:type username: str
	:type password: str
	:type servers_public_key: Crypto.PublicKey.RSA.RsaKey
	:type my_private_key: Crypto.PublicKey.RSA.RsaKey

	:returns: the response command of the server and the following data (can be a bad status and can also be a
			  session id if the login went fine).
	:rtype: tuple
	"""

    cmd, status = send_recv_msg(conn, REQUEST_PROTOCOL['sign in'],
                                concat_username_password(username, password), '', servers_public_key, my_private_key)
    # I placed a placeholder ('') as the session id because the user still doesn't have one, he does this request to
    # get one...

    return cmd, status  # might not actually a status.. it might be a session id


def login_signin_tries(login_or_signin, client, username, password, servers_public_key, my_private_key):
    """
	Handles the user's request to login or to sign in. Gives the user x chances to enter the username and password,
	and if the client changes the source code to give him infinite tries - it doesn't matter because the server
	detects the amount of login requests the user tries and also detects DoS / DdoS attacks.

	:param login_or_signin: a number ('1' - Login, '2' - Sign in).
	:param client: the client's connection to the server.
	:param username: client's username.
	:param password: client's password.
	:param servers_public_key: used to encrypt the login info.
	:param my_private_key: client's private key that is used to decrypt the message that the server sent.

	:type login_or_signin: str
	:type client: socket
	:type username: str
	:type password: str
	:type servers_public_key: Crypto.PublicKey.RSA.RsaKey
	:type my_private_key: Crypto.PublicKey.RSA.RsaKey

	:returns: a session id if the client got his username ad password right in x tries, OR False if he didn't.
	:rtype: str or bool
	"""

    cmd, status = None, None  # place holders... will be assigned soon

    if login_or_signin == '1':  # 1 - Login

        cmd, status = login(client, username, password, servers_public_key, my_private_key)

        if cmd == RESPONSE_PROTOCOL['status']:
            # means that the status variable does NOT contain a session id, and DOES contain an error status.
            check_status(status)

            for i in range(MAX_AMOUNT_OF_LOGIN_TRIES - 1):
                # if the user changed the code in his side & the server detects that his input is wrong - he keeps
                # entering username and password till it'll be correct (he has 5 tries).
                username, password = get_username_password('1')
                cmd, status = login(client, username, password, servers_public_key, my_private_key)
                if cmd == RESPONSE_PROTOCOL['session id']:  # means that the status variable contains a session id.
                    break
                check_status(status)

    elif login_or_signin == '2':  # 2 - Sign in

        cmd, status = sign_in(client, username, password, servers_public_key, my_private_key)

        if cmd == RESPONSE_PROTOCOL['status']:
            check_status(status)

            for i in range(MAX_AMOUNT_OF_LOGIN_TRIES - 1):
                # if the user changed the code in his side & the server detects that his input is wrong - he keeps
                # entering username and password till it'll be correct (he has 5 tries).
                username, password = get_username_password('2')
                cmd, status = sign_in(client, username, password, servers_public_key, my_private_key)
                if cmd == RESPONSE_PROTOCOL['session id']:
                    break
                check_status(status)

    if cmd == RESPONSE_PROTOCOL['session id']:
        # if after tries <= x tries the cmd finally indicates that the status variable contains a session id- return it:
        return status  # status is the session ID
    else:  # something went wrong... the user didn't get his username and password in the given tries:
        return ''


def request_page(client, session_id, servers_public_key, my_private_key):
    """
	Requests the server for a page (the menu page).

	:param client: the client's connection to the server from the client-side.
	:param session_id: the client's session_id, used in order to verify that the user is logged before giving him the page.
	:param servers_public_key: used to encrypt the data so only the server can decrypt it.
	:param my_private_key: client's private key that is used to decrypt the message that the server sent.

	:type client: socket.connection
	:type session_id: str
	:type servers_public_key: Crypto.PublicKey.RSA.RsaKey
	:type my_private_key: Crypto.PublicKey.RSA.RsaKey

	:returns: If the client got the page successfully - returns the page in plain text, otherwise - it returns None.
	:rtype: str or None
	"""

    # status can be a bad status or a page - depending on the cmd:
    cmd, status = send_recv_msg(client, REQUEST_PROTOCOL['get'], '', session_id, servers_public_key, my_private_key)
    if cmd == RESPONSE_PROTOCOL['page']:
        # meaning that the request of the page was successful, and the status variable contains the page.
        print_page(status)
        return status
    else:
        check_status(status)
        exit()
        return None


def print_page(page):
    """
	Prints the menu page in a nice format.

	:param page: the page (menu) in plain-text.

	:type page: str

	:returns: None
	"""

    print('\n==================================================================================================\n')
    print(page)
    print('\n==================================================================================================\n')


def print_title_of_app():
    print(r"""
    
 __          __    _                                   _              __  __                                            
 \ \        / /   | |                                 | |            |  \/  |                                           
  \ \  /\  / /___ | |  ___  ___   _ __ ___    ___     | |_  ___      | \  / | _   _                                     
   \ \/  \/ // _ \| | / __|/ _ \ | '_ ` _ \  / _ \    | __|/ _ \     | |\/| || | | |                                    
    \  /\  /|  __/| || (__| (_) || | | | | ||  __/    | |_| (_) |    | |  | || |_| |                                    
     \/  \/  \___||_| \___|\___/ |_| |_| |_| \___|     \__|\___/     |_|  |_| \__, |                                    
                                                                               __/ |                                    
                                                                              |___/                                     
   ____          _  _                   _______           _              __  __                                         
  / __ \        | |(_)                 |__   __|         | |            |  \/  |                                        
 | |  | | _ __  | | _  _ __    ___        | |  __ _  ___ | | __ ___     | \  / |  __ _  _ __    __ _   __ _   ___  _ __ 
 | |  | || '_ \ | || || '_ \  / _ \       | | / _` |/ __|| |/ // __|    | |\/| | / _` || '_ \  / _` | / _` | / _ \| '__|
 | |__| || | | || || || | | ||  __/       | || (_| |\__ \|   < \__ \    | |  | || (_| || | | || (_| || (_| ||  __/| |   
  \____/ |_| |_||_||_||_| |_| \___|       |_| \__,_||___/|_|\_\|___/    |_|  |_| \__,_||_| |_| \__,_| \__, | \___||_|   
                                                                                                       __/ |            
                                                                                                      |___/             
  Github Repository: https://github.com//Yahel05B//online-tasks-manager/ 
    """)


def main():
    # ask for the user if he would like to login or sign in till he chooses correctly: these next parts are before the
    # connection to the server so the client won't be connected for much time and only tries to get his details
    # right... :

    try:
        login_or_signin = input('1 - Login\n2 - Sign in\n\n> ')
        while login_or_signin not in ['1', '2']:
            login_or_signin = input('1 - Login\n2 - Sign in\n\n> ')
    except (KeyboardInterrupt, ConnectionResetError):
        login_or_signin = ''  # doesn't matter, there is an exit() function later to terminate the program anyways.
        print('Bye Bye :)')
        exit()

    # get the user's username and password:
    username, password = get_username_password(login_or_signin)

    # now, when connecting to the server, the server will also check if the details are valid in the server-side (
    # client might have changed his client-side validation functions):
    client = setup()  # connects to the server and returns the client-side socket

    # Encryption and Decryption Keys:
    public_key, private_key = handle_keys(Machine.C)  # before processing, decrypt the msg using the private key
    servers_public_key = trade_keys(client, public_key)  # before sending, encrypt the msg using the server's public_key

    # the session id will be present at every client request in order to authenticate that it's him:
    session_id = login_signin_tries(login_or_signin, client, username, password, servers_public_key, private_key)
    # if login fails, the session_id variable will be False and then the program will exit... else, the session_id
    # variable will contain a sid.

    if session_id:
        # when the code reaches here, the user is logged-in (assuming he didn't change the source code).

        page = request_page(client, session_id, servers_public_key, private_key)
        # if the request was successful, I know that the user it logged in legit. By saving the page to a variable -
        # I don't need to request the server every time to see the same single page.
        while True:
            # while the user-input is incorrect - it'll keep asking for new input:
            try:
                task = input('> ')
                while not validate_task_num(task):
                    print('Invalid Task, Please Try Again...')
                    task = input('> ')
            except (KeyboardInterrupt, ConnectionResetError):
                disconnect(client, session_id, servers_public_key, private_key)
                task = ''  # doesn't matter, there is an exit() function later to terminate the program anyways.

            # when the code reaches here, the user-input (task number) is valid.
            do_task(client, task, session_id, servers_public_key, private_key)

            print_page(page)  # for the next iteration...

    client.close()


if __name__ == '__main__':
    main()
