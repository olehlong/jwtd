import jwtd.jwt;

void main() {
	version(unittest) {
		import std.stdio;

		version(UseBotan) {
			writeln("Encryption library: Botan.");
		}

		version(UseOpenSSL) {
			writeln("Encryption library: OpenSSL.");
		}

		writeln("All unit tests were successful.");
	}
}