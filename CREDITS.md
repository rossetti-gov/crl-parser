# Credits, Notes, and Reference

Documentation:

  + [OpenSSL Docs](https://www.openssl.org/docs/man1.1.0/apps/crl.html)
  + [Ruby OpenSSL Source](https://github.com/ruby/openssl)
  + [Ruby `OpenSSL::X509::CRL` Docs](https://ruby-doc.org/stdlib-2.4.2/libdoc/openssl/rdoc/OpenSSL/X509/CRL.html)
  + [Ruby `OpenSSL::X509::Revoked` Docs](http://ruby-doc.org/stdlib-2.5.0/libdoc/openssl/rdoc/OpenSSL/X509/Revoked.html)
  + [Ruby `OpenSSL::X509::Extension` Docs](http://ruby-doc.org/stdlib-2.5.0/libdoc/openssl/rdoc/OpenSSL/X509/Extension.html)
  + [Ruby `OpenSSL::BN` (Serial Number) Docs](http://ruby-doc.org/stdlib-2.4.0/libdoc/openssl/rdoc/OpenSSL/BN.html)

Tutorials, examples, and guides:

  + [Parsing a CRL with OpenSSL](https://langui.sh/2010/01/10/parsing-a-crl-with-openssl/)
  + [Reading CRLs in Windows with Ruby](http://seanbachelder.me/2016/06/17/reading-crls-in-windows-with-ruby.html)

## Initial Parsing Attempts

When opening the CRL file in a text editor, it appears to be binary, which would suggest it's in DER format (not PEM format).

Using the command-line to parse a CRL from file:

```sh
openssl crl -inform DER -text -noout -in data/20180301-1544/DODIDCA_42.crl
```

Produces output like:

```
Certificate Revocation List (CRL):
        Version 2 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: /C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=DOD ID CA-42
        Last Update: Mar  1 08:00:00 2018 GMT
        Next Update: Mar  8 17:00:00 2018 GMT
        CRL extensions:
            X509v3 Authority Key Identifier:
                keyid:32:A0:00:CA:59:8B:C4:CE:7C:7B:DB:DE:19:2A:10:8A:86:41:D1:E3

            X509v3 CRL Number:
                1997
Revoked Certificates:
    Serial Number: 17FFFB
        Revocation Date: Dec  7 05:19:12 2017 GMT
        CRL entry extensions:
            X509v3 CRL Reason Code:
                Affiliation Changed
    ...
    Serial Number: 0C00A5
        Revocation Date: May 26 13:58:47 2017 GMT
        CRL entry extensions:
            X509v3 CRL Reason Code:
                Affiliation Changed
            Invalidity Date:
                May 26 13:57:22 2017 GMT
    ...
    Serial Number: 0C0002
        Revocation Date: Dec 18 16:34:13 2017 GMT
        CRL entry extensions:
            X509v3 CRL Reason Code:
                Superseded
    Signature Algorithm: sha256WithRSAEncryption
        79:47:e1:e0:43:3e:75:0a:e6:f5:f1:c3:c7:42:1c:9b:63:ab:
        33:d0:7c:d0:85:98:81:74:65:25:7e:3e:b3:42:b0:e2:b3:2c:
        75:14:be:5d:04:33:65:df:48:96:7f:f0:a8:33:55:be:53:51:
        10:3e:9a:e7:b5:1e:0b:98:b4:1d:17:c9:ad:3b:23:63:c3:90:
        db:d1:44:9d:65:51:59:f9:57:18:b4:52:9e:8e:19:e0:6f:a4:
        67:bf:0a:2c:57:a6:0d:e8:c3:9f:4c:2a:bb:a3:be:47:9b:04:
        69:8e:bb:88:23:ea:ca:93:06:d3:19:c3:34:3a:36:55:e9:99:
        f2:47:87:44:e5:c4:84:af:8f:06:9b:8d:99:f4:60:9e:b2:ba:
        8a:a9:b7:48:6a:77:e9:1f:f7:51:67:f1:e5:51:58:27:22:5c:
        8e:9d:39:f6:b1:d9:56:29:52:a3:da:ad:11:68:fd:40:89:cf:
        f5:5f:8c:de:f3:85:16:34:9c:0b:89:71:e6:58:76:82:ff:45:
        44:40:9a:f7:6a:fa:db:4e:50:72:31:21:cd:8a:0c:3b:f2:57:
        ed:19:e5:56:f5:19:49:10:64:67:ae:af:ef:04:6e:55:90:c7:
        32:35:c3:84:82:3a:59:cf:63:7d:d2:c4:8f:24:90:f0:92:90:
        f8:32:f5:2f
```

The `Revoked Certificates` don't seem to be sorted by `Revocation Date`.

## Ruby Parsing Attempts

File sizes:

  + `.crl`: 13M
  + `metadata.json`: 315B
  + `revocations.json`: 75M (with extensions)
  + `revocations.csv`: 9.1M (without extensions)
