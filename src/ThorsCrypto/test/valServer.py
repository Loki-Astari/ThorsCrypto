from scramp import ScramMechanism
import base64

USERNAME = input('UserName (user)? ').strip() or 'user'
PASSWORD = input('Password (pencil)? ').strip() or 'pencil'
mech     = input('MECHANISMS (SCRAM-SHA-1)? ').strip() or 'SCRAM-SHA-1'
salt64   = input('Salt Base64 encoded (QSXCR+Q6sek8bf92)? ').strip() or 'QSXCR+Q6sek8bf92'
iter     = int(input('Iterations (4096)? ').strip() or '4096')

SALT     = base64.decodebytes(salt64.encode('ascii')) if salt64 != None else None


# Define your own function for retrieving the authentication information
# from the database given a username

mechanism = ScramMechanism(mechanism=mech)
salt, stored_key, server_key, iteration_count = mechanism.make_auth_info(PASSWORD, iter, SALT)

db = {}
db[USERNAME] = salt, stored_key, server_key, iteration_count

def dbAccess(username):
     return db[username]

# Make the SCRAM server
server = mechanism.make_server(dbAccess, None, '3rfcNHYJY1ZVvWVs7j')

cfirst = input('Client First (n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL)? ') or 'n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL'
server.set_client_first(cfirst)
sfirst = server.get_server_first()
print('Server First: ' + sfirst)

cfinal = input('Client Final (c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=)? ') or 'c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts='
server.set_client_final(cfinal)
sfinal = server.get_server_final()
print('Server Final: ' + sfinal)


