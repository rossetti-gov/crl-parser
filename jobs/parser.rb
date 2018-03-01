
#require "openssl"

CRL_URL = "http://crl.disa.mil/crl/DODIDCA_42.crl" # this is the only CRL URL I know about at the moment.

puts "FETCHING CERTIFICATE REVOCATION LIST FROM #{CRL_URL}"

crl_filepath = "./data/20180301-1544/DODIDCA_42.crl" # NOTE: file when opened with a text editor appears to be binary, which would indicate the DER format (not the PEM format)

puts "DOWNLOADED CERTIFICATE REVOCATION LIST TO #{crl_filepath}"

#parsed_crl = R509::CRL::SignedList.new(crl)
