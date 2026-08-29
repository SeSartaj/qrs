the app should have the following: 


## certificate build: 
specify algorithm, specify fields, for each feild specify if during signing or during verification, type, name of the document, name of the issuer. valid before, valid after. based on this, two files are generated, one having private key, another is the public certificate file. the private one secured using a passcode or fingerprint. the public certificate file contains the public key and other certificate content. the certificate content itself are signed using the private key. the private certificate file contains all the content of public certificate. 

the certificate can also be signed by a root certificate. if signed by root certificate, when the certificate is added to the verifier app, they first verify the signature of the root. if the root doesn't exist, the certificate is considered invalid. 


## the signing phase
user selects or loads the private certificate file, and based on the document fields show user the input fields. user inserts the data and a signed data message is generated, which can then be outputed to different barcode forms. for now we will use qr code for the output. make sure the data is compressed before qr code generation. 


## the public certificate loading step
in the configurations, user can click add certificate. he can upload the file. 


## the verification step
user scans a bar code, and the bar code is read, version of the protocol is read. after that the certificate id is read, the certificate is found, based on the certificate the payload is decoded, if any input is required, that is asked in popup, then the data is verified against the signature. after that it is checked if the document is in the revocation list. then using the information/ metadata in the public certificate, the data is presented along with valid, invalid, revoked or expired states. 