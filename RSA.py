from base64 import b64encode, b64decode
from functools import partial
try:
	from math import ceil, gcd, lcm, log
#handles Python versions earlier than 3.9
except ImportError:
	from math import ceil, gcd, log
	def lcm(a, b):
		'''
		from stackoverflow.com/a/51716959
		'''
		return (a * b) // gcd(a, b)
#need keyword arguments for partial
def kw_pow(base=None, exponent=None, modulus=None):
	if base is None or exponent is None:
		raise AssertionError
	if modulus is None:
		return pow(base, exponent)
	return pow(base, exponent, modulus)

from sys import setrecursionlimit
setrecursionlimit(2000)
from secrets import randbits, randbelow

from gmpy2 import is_prime

def load_key_file(filename):
	with open(filename, "r") as f:
		return [int(b64decode(x)) for x in f.read().splitlines()[0].split(";")]

def save_to_key_file(filename, key):
	with open(filename, "w") as f:
		def to_bytes(x):
			return bytes(str(x), "ascii")

		f.write(b64encode(to_bytes(key[0])).decode("ascii") + ";" + b64encode(to_bytes(key[1])).decode("ascii"))


mode = 0
while not (1 <= mode <= 3):
	mode = int(input("Would you like to 1. Generate a new key pair 2. Encrypt a message 3. Decrypt a message  ")[0])
if mode == 1:
	def modular_multiplicative_inverse(multiplier, modulus):
		'''
		Finds a number c such that (c * multiplier) mod modulus = 1
		multiplier and modulus MUST be coprime (ie have a gcd of 1)
		'''
		def extended_euclidean_algorithm(a, b):
			'''
			Returns a tuple (x, y) such that ax + by = 1
			a and b MUST be coprime
			'''
			if a == 0:
				actual_x = 0
				actual_y = 1
			else:
				b_div_a, b_mod_a = divmod(b, a)
				x, y = extended_euclidean_algorithm(b_mod_a, a)
				actual_x = y - (b_div_a * x)
				actual_y = x

			return (actual_x, actual_y)


		c = extended_euclidean_algorithm(multiplier, modulus)[0]
		return c % modulus

	p = 4
	q = 4
	priv_file = input("Enter a filename (including extension) for the private key  ")
	pub_file = input("Enter a filename (including extension) for the public key  ")

	print("Generating a random prime p")
	while not is_prime(p):
		p = randbits(1024)
	print("Generating a random prime q")
	while not is_prime(q):
		q = randbits(1024)
	print("Multiplying p and q to get n")
	#n will be roughly 2048 bits
	n = p * q

	print("Generating encryption key")
	totient = lcm(p-1, q-1)
	e = totient
	while gcd(e, totient) != 1:
		e = randbelow(totient)

	print("Generating decryption key")
	d = modular_multiplicative_inverse(e, totient)
	print("Cleaning up")
	del p, q, totient

	public_key = (e, n)
	private_key = (d, n)
	save_to_key_file(pub_file, public_key)
	print("Saved public key to " + pub_file)
	save_to_key_file(priv_file, private_key)
	print("Saved public key to " + priv_file)
elif mode == 2:
	e, n = load_key_file(input("Enter the filename (including extension) of the public key  "))
	plaintext = input("Enter the message that you would like to encrypt  ")
	#splits text up into 100 byte blocks
	blocks_of_plaintext = []
	i = 100
	while i <= len(plaintext):
		blocks_of_plaintext.append(plaintext[(i-100):i])
		i += 100
	if len(plaintext) % 100 != 0:
		blocks_of_plaintext.append(plaintext[(i-100):-1] + plaintext[-1])
	
	blocks_of_plaintext_as_ints = map(lambda x: int.from_bytes(bytes(x, "utf-8"), byteorder="little"), blocks_of_plaintext)
	ciphertext = map(partial(kw_pow, exponent=e, modulus=n), blocks_of_plaintext_as_ints)
	for block in ciphertext:
		print(block)
elif mode == 3:
	d, n = load_key_file(input("Enter the filename (including extension) of the private key  "))
	blocks_of_ciphertext = [int(input("Please enter the message that you would like to decrypt one block at a time, press return without entering anything once you run out of blocks "))]
	try:
		while True:
			blocks_of_ciphertext.append(int(input("Enter the next block of ciphertext  ")))
	except ValueError:
		pass

	plaintext_as_ints = map(partial(kw_pow, exponent=d, modulus=n), blocks_of_ciphertext)
	#takes log base 256 as log256(x) is the same as log2(x)/8 which is the minimum number of bytes needed to represent x
	plaintext = [x.to_bytes(ceil(log(x, 256)), "little").decode("utf-8") for x in plaintext_as_ints]
	print("".join(plaintext))
else:
	raise AssertionError