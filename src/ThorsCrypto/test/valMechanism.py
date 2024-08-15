from scramp import ScramClient, ScramMechanism
import binascii
import base64

PASSWORD = input('Password (pencil)? ').strip() or 'pencil'
mech     = input('MECHANISMS (SCRAM-SHA-1)? ').strip() or 'SCRAM-SHA-1'
salt64   = input('Salt Base64 encoded (\'rOprNGfwEbeRWgbNEkqO\')? ').strip() or 'rOprNGfwEbeRWgbNEkqO'
iter     = int(input('Iteration Count (4096)? ').strip() or '4096')

SALT     = base64.decodebytes(salt64.encode('ascii')) if salt64 != None else None
MECHANISMS = [mech]

# Choose a mechanism for our server
mechanism = ScramMechanism(mechanism=mech)  # Default is SCRAM-SHA-256
salt, stored_key, server_key, iteration_count = mechanism.make_auth_info(PASSWORD, iter, SALT)

print( 'pass: >' + PASSWORD + '<')
print( 'mech: >' + mech     + '<')
print( '--------------')
print( 'Salt:       >' + binascii.hexlify(SALT).decode('utf-8') + '<')
print( 'Stored Key: >' + binascii.hexlify(stored_key).decode('utf-8') + '<')
print( 'Server Key: >' + binascii.hexlify(server_key).decode('utf-8') + '<')
print( 'Iter:       >' + str(iteration_count) + '<')

