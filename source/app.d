import jwtd.jwt;

void main() {
	version(unittest) {
		import std.stdio;

		version(UseBotan) {
			import botan.libstate.init;
			LibraryInitializer init;
			writeln("Encryption library: Botan.");
		}

		version(UseOpenSSL) {
			writeln("Encryption library: OpenSSL.");
		}
		
		version(UsePhobos) {
			writeln("Encryption library: Phobos.");
		}

		writeln("All unit tests were successful.");
	}
}
