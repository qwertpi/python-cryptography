from secrets import randbelow

from scapy.layers.inet import UDP, IP
from scapy.packet import Raw
from scapy.sendrecv import send, sniff

#this is difie-hellman group 16 https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html#rfc.section.3.9
def generate_p():
	#sourced from https://datatracker.ietf.org/doc/html/rfc3526#section-5
	p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF", 16)
	return p

def generate_g():
	return 2

def generate_personal_secret(p):
	#as per 5.6.1.1.1 of NIST SP 800-56A Rev. 3
	#int division as we want an int anyway and a float would overflow
	q = (p - 1)//2
	return randbelow(q)
	
def modular_exponenate(value, power, modulus):
	#use built in pow for efficiency
	return pow(value, power, modulus)


ALICE = input("Are you Alice? y/n  ")[0].lower() == "y"
BOB = not ALICE
CLIENT_IP = input("Enter the IP of the other party  ")

if ALICE:
	input("Press enter once you have started Bob  ")
	p = generate_p()
	g = generate_g()
	print("Sharing p and g")
	send(IP(dst=CLIENT_IP)/UDP(dport=53070)/f"{p};{g}", iface="wlan0")

	personal_secret = generate_personal_secret(p)
	print("Sharing public value")
	send(IP(dst=CLIENT_IP)/UDP(dport=53070)/f"{modular_exponenate(g, personal_secret, p)}", iface="wlan0")
	
	bobs_public_value = int(sniff(filter=f"src host {CLIENT_IP} and udp dst port 53069", count=1, iface="wlan0")[0][Raw].load.decode("ascii"))
	print("Calculating shared secret")
	shared_secret = modular_exponenate(bobs_public_value, personal_secret, p)
	print(shared_secret)

if BOB:
	p, g = map(int, sniff(filter=f"src host {CLIENT_IP} and udp dst port 53070", count=1, iface="wlan0")[0][Raw].load.decode("ascii").split(";"))
	print("Received p and g")
	
	alices_public_value = int(sniff(filter=f"src host {CLIENT_IP} and udp dst port 53070", count=1, iface="wlan0")[0][Raw].load.decode("ascii"))

	personal_secret = generate_personal_secret(p)
	print("Sharing public value")
	send(IP(dst=CLIENT_IP)/UDP(dport=53069)/f"{modular_exponenate(g, personal_secret, p)}", iface="wlan0")
	
	print("Calculating shared secret")
	shared_secret = modular_exponenate(alices_public_value, personal_secret, p)
	print(shared_secret)
