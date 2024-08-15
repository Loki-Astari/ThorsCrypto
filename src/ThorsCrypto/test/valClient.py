from scramp import ScramClient
import base64

USERNAME = input('UserName (user)? ').strip() or 'user'
PASSWORD = input('Password (pencil)? ').strip() or 'pencil'
mech     = input('MECHANISMS (SCRAM-SHA-1)? ').strip() or 'SCRAM-SHA-1'
Nonce    = input('Nonse Base64 encoded (fyko+d2lbbFgONRv9qkxdawL)? ').strip() or 'fyko+d2lbbFgONRv9qkxdawL'

MECHANISMS = [mech]

print()
print()
print('Username >' + USERNAME + '<')
print('Password >' + PASSWORD + '<')
print('Meachani >' + mech     + '<')
print('Nonce    >' + Nonce    + '<')
client = ScramClient(MECHANISMS, USERNAME, PASSWORD, channel_binding=None, c_nonce=Nonce)

# Get the client first message and send it to the server
cfirst = client.get_client_first()
print('Get Client First: >' + cfirst + '<')


serverResponse = input('What is the server response?').strip()
print()
print('SR       >' + serverResponse + '<')
client.set_server_first(serverResponse)

cfinal = client.get_client_final()
print('Get Client Final: result:          >' + cfinal + '<')

serverResponse = input('What was the server response?')
client.set_server_final(serverResponse)

#
# If the server response is not correct it will throw an exception
# and thus never get here.
print('All Good');

