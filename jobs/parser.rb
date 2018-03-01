require "openssl"
require "pry"

CRL_URL = "http://crl.disa.mil/crl/DODIDCA_42.crl" # this is the only CRL URL I know about at the moment.

puts "FETCHING CERTIFICATE REVOCATION LIST FROM #{CRL_URL}..."

crl_filepath = "./data/20180301-1544/DODIDCA_42.crl" # NOTE: file when opened with a text editor appears to be binary, which would indicate the DER format (not the PEM format)

puts "DOWNLOADED CERTIFICATE REVOCATION LIST TO #{crl_filepath}..."

puts "PARSING CRL FILE..."

crl = OpenSSL::X509::CRL::new(File.read(crl_filepath))

puts "... ISSUER: #{crl.issuer.to_s}"
puts "... VERSION: #{crl.version.to_s}"
puts "... LAST UPDATE: #{crl.last_update.to_s}"
puts "... NEXT UPDATE: #{crl.next_update.to_s}"
revoked_certs = crl.revoked # memoize for performance
puts "... REVOKED CERTIFICATE COUNT: #{revoked_certs.count}"

#puts "... LOOPING THROUGH REVOKED CERTIFICATES ..."

#crl.revoked.each do |revoked_cert|
#
#end

puts "INVESTIGATING FIRST CERTIFICATE..."

r = revoked_certs.first

puts "... SERIAL: #{r.serial.to_s}"
puts "... TIME: #{r.time.to_s}"
puts "... EXTENSIONS (#{r.extensions.count}):"
r.extensions.each do |ext|
  puts "   ... #{ext.to_h}"
end
