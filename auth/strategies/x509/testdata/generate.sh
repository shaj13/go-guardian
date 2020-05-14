# install 
# curl https://pkg.cfssl.org/R1.2/cfssl_linux-amd64 -o /usr/local/bin/cfssl
# curl https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64 -o /usr/local/bin/cfssljson


# generate root 
cfssl gencert -initca ca.json | cfssljson -bare ca

# generate intermediate 
cfssl gencert -initca intermediate.json | cfssljson -bare intermediate
cfssl sign -ca ca.pem -ca-key ca-key.pem -config cfssl.json -profile=intermediate intermediate.csr | cfssljson -bare intermediate


# genergenerate client using intermediate  
cfssl gencert -ca intermediate.pem -ca-key intermediate-key.pem -config cfssl.json -profile=valid client.json | cfssljson -bare client_intermediate_valid
cfssl gencert -ca intermediate.pem -ca-key intermediate-key.pem -config cfssl.json -profile=expired client.json | cfssljson -bare client_intermediate_expired
cfssl gencert -ca intermediate.pem -ca-key intermediate-key.pem -config cfssl.json -profile=future client.json | cfssljson -bare client_intermediate_future

# generate client
cfssl gencert -initca client.json | cfssljson -bare client
cfssl sign -ca ca.pem -ca-key ca-key.pem -config cfssl.json -profile=valid client.csr | cfssljson -bare client_valid
cfssl sign -ca ca.pem -ca-key ca-key.pem -config cfssl.json -profile=expired client.csr | cfssljson -bare client_expired
cfssl sign -ca ca.pem -ca-key ca-key.pem -config cfssl.json -profile=future client.csr | cfssljson -bare client_future

 # clean 
 rm -rf *.csr 
 rm -rf *-key.pem 

 for f in *.pem; do 
    mv -- "$f" "${f%.pem}"
done