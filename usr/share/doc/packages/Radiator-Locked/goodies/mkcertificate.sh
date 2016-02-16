#!/bin/sh 

CA_PL=/usr/lib/ssl/misc/CA.pl
if [ ! -x $CA_PL ]; then
    echo Could not find CA.pl in $CA_PL
    exit 1
fi

SSL=/usr/local/ssl 
export PATH=${SSL}/bin/:${SSL}/misc:/usr/share/ssl/misc:${PATH} 
export LD_LIBRARY_PATH=${SSL}/lib 

# needed if you need to start from scratch otherwise the CA.pl -newca command doesn't copy the new 
# private key into the CA directories 
rm -rf demoCA 
mkdir demoCA
echo 01 > demoCA/serial

echo "*********************************************************************************" 
echo "Creating self-signed private key and certificate" 
echo "When prompted override the default value for the Common Name field" 
echo "*********************************************************************************" 

echo # Generate a new self-signed certificate. 
# After invocation, newreq.pem will contain a private key and certificate 
# newreq.pem will be used in the next step 
openssl req -new -x509 -keyout newreq.pem -out newreq.pem -days 730 -passin pass:whatever -passout pass:whatever -sha256 -newkey rsa:2048

echo "*********************************************************************************" 
echo "Creating a new CA hierarchy (used later by the "ca" command) with the certificate" 
echo "and private key created in the last step" 
echo "*********************************************************************************" 
echo 
echo "newreq.pem" | $CA_PL -newca >/dev/null 

echo "*********************************************************************************" 
echo "Creating ROOT CA" 
echo "*********************************************************************************" 
echo 

# Create a PKCS#12 file, using the previously created CA certificate/key 
# The certificate in demoCA/cacert.pem is the same as in newreq.pem. Instead of
# using "-in demoCA/cacert.pem" we could have used "-in newreq.pem" and then omitted 
# the "-inkey newreq.pem" because newreq.pem contains both the private key and certificate 
openssl pkcs12 -export -in demoCA/cacert.pem -inkey newreq.pem -out root.p12 -cacerts -passin pass:whatever -passout pass:whatever 

# parse the PKCS#12 file just created and produce a PEM format certificate and key in root.pem 
openssl pkcs12 -in root.p12 -out root.pem -passin pass:whatever -passout pass:whatever 

# Convert root certificate from PEM format to DER format 
openssl x509 -inform PEM -outform DER -in root.pem -out root.der 

echo "*********************************************************************************" 
echo "Creating client private key and certificate" 
echo "When prompted enter the client name in the Common Name field. This is the same" 
echo " used as the Username in Radiator user database" 
echo "*********************************************************************************" 
echo # Request a new PKCS#10 certificate. 
# First, newreq.pem will be overwritten with the new certificate request 
openssl req -new -keyout newreq.pem -out newreq.pem -days 730 -passin pass:whatever -passout pass:whatever -sha256 -newkey rsa:2048

# Sign the certificate request. The policy is defined in the openssl.cnf file. # The request generated in the previous step is specified with the -infiles option and 
# the output is in newcert.pem 
# The -extensions option is necessary to add the OID for the extended key for client authentication 
openssl ca -policy policy_anything -days 730 -out newcert.pem -passin pass:whatever -key whatever -extensions xpclient_ext -extfile xpextensions -in newreq.pem -md sha256

# Create a PKCS#12 file from the new certificate and its private key found in newreq.pem 
# and place in file cert-clt.p12 Version 1.0.2, April 24, 2002

openssl pkcs12 -export -in newcert.pem -inkey newreq.pem -out cert-clt.p12 -clcerts -passin pass:whatever -passout pass:whatever 

# parse the PKCS#12 file just created and produce a PEM format certificate and key in cert- clt.pem 
openssl pkcs12 -in cert-clt.p12 -out cert-clt.pem -passin pass:whatever -passout pass:whatever 

# Convert certificate from PEM format to DER format 
openssl x509 -inform PEM -outform DER -in cert-clt.pem -out cert-clt.der 

echo "*********************************************************************************" 
echo "Creating server private key and certificate" 
echo "When prompted enter the server name in the Common Name field." 
echo "*********************************************************************************" 
echo 

# Request a new PKCS#10 certificate. 
# First, newreq.pem will be overwritten with the new certificate request 
openssl req -new -keyout newreq.pem -out newreq.pem -days 730 -passin pass:whatever -passout pass:whatever -sha256 -newkey rsa:2048

# Sign the certificate request. The policy is defined in the openssl.cnf file.
# The request generated in the previous step is specified with the -infiles option and 
# the output is in newcert.pem 
# The -extensions option is necessary to add the OID for the extended key for server authentication 
openssl ca -policy policy_anything -days 730 -out newcert.pem -passin pass:whatever -key whatever -extensions xpserver_ext -extfile xpextensions -in newreq.pem -md sha256

# Create a PKCS#12 file from the new certificate and its private key found in newreq.pem 
# and place in file cert-srv.p12 
openssl pkcs12 -export -in newcert.pem -inkey newreq.pem -out cert-srv.p12 -clcerts -passin pass:whatever -passout pass:whatever 

# parse the PKCS#12 file just created and produce a PEM format certificate and key in cert-srv.pem 
openssl pkcs12 -in cert-srv.p12 -out cert-srv.pem -passin pass:whatever -passout pass:whatever 

# Convert certificate from PEM format to DER format 
openssl x509 -inform PEM -outform DER -in cert-srv.pem -out cert-srv.der 

#clean up 
rm newcert.pem newreq.pem

