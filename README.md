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
	
#### Botan
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
#### Using Botan
```
dub build --config=botan
```

## Testing

#### Using OpenSSL
```
dub test --config=unittest-openssl
```
### Using Botan
```
dub test --config=unittest-botan
```





