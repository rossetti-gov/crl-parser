require "openssl"
require "json"
require "pry"

CRL_URL = "http://crl.disa.mil/crl/DODIDCA_42.crl" # this is the only CRL URL I know about at the moment.
puts "FETCHING CERTIFICATE REVOCATION LIST FROM #{CRL_URL}..."

downloaded_at = "20180301-1544" #TODO: vary over time
crl_dir = "./data/#{downloaded_at}"
crl_filepath = File.join(crl_dir, "DODIDCA_42.crl")
puts "DOWNLOADING CERTIFICATE REVOCATION LIST TO #{crl_filepath}..."

puts "PARSING CERTIFICATE REVOCATION LIST..."

crl = OpenSSL::X509::CRL::new(File.read(crl_filepath))
revocations = crl.revoked
revocations = revocations.sort_by{ |revocation| revocation.time }

metadata = {
  issuer: crl.issuer.to_s,
  version: crl.version.to_s,
  last_update: crl.last_update.to_s,
  next_update: crl.next_update.to_s,
  revocations_count: revocations.count, #> 306926
  earlist_revocation_at: revocations.first.time,
  latest_revocation_at: revocations.last.time
}

pp metadata

metadata_filepath = File.join(crl_dir, "metadata.json")
File.open(metadata_filepath, "w") do |f|
  f.write(JSON.pretty_generate(metadata))
end

puts "PARSING REVOKED CERTIFICATES..."

revs = [] # maybe faster than mapping 300K items in place...
revocations.each do |revocation|
  revs << {
    serial_number: revocation.serial.to_s,
    revoked_at: revocation.time.to_s,
    extensions: revocation.extensions.map{ |ext| ext.to_h }
  }
end

revocations_filepath = File.join(crl_dir, "revocations.json")
File.open(revocations_filepath ,"w") do |f|
  f.write(JSON.pretty_generate(revs)) # is there a way to write incrementally?
end
