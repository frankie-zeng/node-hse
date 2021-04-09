var assert = require('assert');
var hse = require('./../index');
describe('HSE', function() {
  describe('#HSE test()', function() {
    it('should return openssl version', function() {
        console.log(hse.getVersion())
    });
    it('generate sym key array', function() {
        var symkey = Buffer.from('000102030405060708090a0b0c0d0e0f','hex')
        var keyInfo={
            handle:50,
            keyFlags:hse.HSE_KF_USAGE_ENCRYPT,
            keyCounter:0,
            smrFlags:hse.HSE_KF_SMR_0,
            keyType:hse.HSE_KEY_TYPE_AES
        }
        var ret=hse.importSymKey(0x40000,hse.GET_KEY_HANDLE(hse.HSE_KEY_CATALOG_ID_NVM,0,0),keyInfo,symkey)
        assert.equal(0,ret.err,ret.msg)
        assert.equal(ret.data.indexOf(symkey)>0,true)
    });
    it('generate rsa pub key array', function() {
        const rsaPubKey =
`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx0KfhKB3VgKSUdyrdVE6
J7iSW0EIDAsv81bpKOjtA/Tj9GvSab0eP8+JwFsHTB+ES/Nc0FzAcITsqP4W/XXo
jgcT6M8ROZe0IuynZjI6zkOQFzolPkFJanSCjPgigPNtJDVJoKMmStEM3sj5xB+Q
VMuo/3agd1SBatS9XW6M545znl+YxW42qmjNZXK2/g9xvBF79yEJncGdUa2TnA3Y
tjAx0OPHAsDsFvgpkXe1YAXZ8Og/PHKqeheSkJP5cEKqfF4JIfqJdvQ9jR08ypas
x0lhmbgbVO9LvJ36RflGXHYYCfYx4j0d/O6voKmkxFS2wFgqcDN8En8YgWZTxoQb
6QIDAQAB
-----END PUBLIC KEY-----
`
        var keyInfo={
            handle:50,
            keyFlags:hse.HSE_KF_USAGE_ENCRYPT,
            keyCounter:0,
            smrFlags:hse.HSE_KF_SMR_0,
            keyType:hse.HSE_KEY_TYPE_RSA_PUB
        }
        var ret=hse.importPubKey(0x40000,hse.GET_KEY_HANDLE(hse.HSE_KEY_CATALOG_ID_NVM,0,0),keyInfo,rsaPubKey)
        assert.equal(0,ret.err,ret.msg)
    });
    it('generate ecc pub key array', function() {
        const eccPubKey =
`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9rWjXOufGTEg3bP8BE5xcNOhfUqe
LM6qj6K32396GjximBW0jPM9VjPsx0JC7+V4mfO63n5jpvsiT8VPvTXTRA==
-----END PUBLIC KEY-----
`
        var keyInfo={
            handle:50,
            keyFlags:hse.HSE_KF_USAGE_ENCRYPT,
            keyCounter:0,
            smrFlags:hse.HSE_KF_SMR_0,
            keyType:hse.HSE_KEY_TYPE_RSA_PUB
        }
        var ret=hse.importPubKey(0x40000,hse.GET_KEY_HANDLE(hse.HSE_KEY_CATALOG_ID_NVM,0,0),keyInfo,eccPubKey)
        assert.equal(0,ret.err,ret.msg)
    });
    it('generate rsa private key array', function() {
        const rsaPrivKey =
`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAx0KfhKB3VgKSUdyrdVE6J7iSW0EIDAsv81bpKOjtA/Tj9GvS
ab0eP8+JwFsHTB+ES/Nc0FzAcITsqP4W/XXojgcT6M8ROZe0IuynZjI6zkOQFzol
PkFJanSCjPgigPNtJDVJoKMmStEM3sj5xB+QVMuo/3agd1SBatS9XW6M545znl+Y
xW42qmjNZXK2/g9xvBF79yEJncGdUa2TnA3YtjAx0OPHAsDsFvgpkXe1YAXZ8Og/
PHKqeheSkJP5cEKqfF4JIfqJdvQ9jR08ypasx0lhmbgbVO9LvJ36RflGXHYYCfYx
4j0d/O6voKmkxFS2wFgqcDN8En8YgWZTxoQb6QIDAQABAoIBAQC0fqgKtmSC979d
AfwaQCLiujFxEd5dMoET9wUrdprD+7/FtymZeKL/AFrycEKS9PWc6uyHHY2AHxhV
GBzxKS4oAUdKms8qkT2uaRpV22gjUVYjhBsaYn9DPBjJ4zc2Acs6gj6YkVDtcqIq
6Hg+7KyL8xO5nNZMYbL9d4m1KZ/fWzL5rHjPr7HcL8HbP5BtEby3zKz/2cLyzpPJ
s+QFjTl981l0AS4g7ezhbNWPuBG0bDl6AnSFYVyQd6DNO44Xp62pSBvwmEIfus6K
yh3UfOnLQy/h6m3Vax/JKzr4jzFfCxsBCGHqn2rGIuvqPylAfv0+YxBMBmR6qYNm
57Uihp8BAoGBAPQwo9xp45HLrvpDto2bzx+he4OL7z9NNXvGziQDbgyw3nRsvXs8
GJS2GCUl7hQme20If7JWaYm6BQpg+Xz00w3q5ib077UUTlLqe7Vi9StRu/MdQ0G9
JP2VbGXQotBYimful2UQrtfOsmXYgCFkvtS8KSjzPvsUXjpx3m5uSKiJAoGBANDl
syKLrGB3//Jq4xuEWi2frdpRCpi7zho4Dm2lJoAQJe8FHvOaEW/1AQT3IOdT6kM0
872disBy2MfJ6vK6nvEtA55U6/EZ3YXFrs/9wZrz6WZFUWZLpMzfjIjSAisttYrb
S+HYaS/Ff+IkviJ25HeWR2Ss0Hw+nnM5zubxikBhAoGBALEVwQ9sPxuRMcDOcEn7
r1ZJ/k+koIkwjdPIld/qGNndPkYCQdtn9o+KCrKN8jzst1+X5TtIjVrS6yrerq9e
wNv7+JJR2LBiHHbnE3W0YQXcTUf+dbLr3zKDNUwU5K3hN+YtUd96HMHmZNuVCT6u
V/Hgzpyi4o6k87zArUU6dzi5AoGAAzNBp0nUfjXYafJRQF6qswA7PZj4PJbD9Yre
Tbe1+0hEDIFblAfMNJbgSR8wFdsnP5hUE5eSRJh90bG6M7XAMZmq8IYEh1EKH76D
ixQsHx+Vd8egE50dDTZvhLkS525v1Yy+gNs74Ut5RhGiCA0iOuLGfThYiU68Rq+g
B9GzeIECgYEA0rS5cVc694gHeKuuUufrBMJJ6HMvWtS2/RNLJ0EhOcVfsPo5KP7a
ncFcn1DP0B+bxSRr7Viz5IKI6j2ZeJb3zMVOn7AS5h7Mcf2u4pnSin7C56s9ksDJ
y3Uv31Ek6iHz/mUmz1uC28ich/lcaNwcYYyODiWE/upq6KEFfwL0QCU=
-----END RSA PRIVATE KEY-----
`
        var keyInfo={
            handle:50,
            keyFlags:hse.HSE_KF_USAGE_ENCRYPT,
            keyCounter:0,
            smrFlags:hse.HSE_KF_SMR_0,
            keyType:hse.HSE_KEY_TYPE_RSA_PAIR
        }
        var ret=hse.importPrivKey(0x40000,hse.GET_KEY_HANDLE(hse.HSE_KEY_CATALOG_ID_NVM,0,0),keyInfo,rsaPrivKey)
        assert.equal(0,ret.err,ret.msg)
    });
  });
});