# jwtd
D implementation of [JSON Web Token](http://jwt.io/).

## Supported algorithms

### OpenSSL
- NONE
- HS256
- HS384
- HS512
- RS256
- RS384
- RS512
- ES256
- ES384
- ES512

#### [Botan](https://github.com/etcimon/botan)
- NONE
- HS256
- HS384
- HS512
- RS256
- RS384
- RS512
- ES256
- ES384
- ES512

**NOTE** - Botan supports private keys just in PKCS#8 format (for RS and ES signatures)

### Phobos
- NONE
- HS256
- HS384
- HS512

## Installation

See [DUB page](http://code.dlang.org/packages/jwtd).

## Building

### Using OpenSSL
```
dub build --config=openssl
```
### Using Botan
```
dub build --config=botan
```
### Using Phobos
```
dub build --config=phobos
```

## Testing

### Using OpenSSL
```
dub test --config=unittest-openssl
```
### Using Botan
```
dub test --config=unittest-botan
```
### Using Phobos
```
dub test --config=unittest-phobos
```
