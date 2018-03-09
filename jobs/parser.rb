require "openssl"
require "open-uri"
require "json"
require "csv"
require "pry"
require "active_support/core_ext/object/try"
#require "base64"

class Parser
  attr_reader :crl_url, :overwrite_crl

  def initialize(crl_url:, overwrite_crl: false)
    @crl_url = crl_url
    @overwrite_crl = overwrite_crl
  end

  def overwrite_crl?
    overwrite_crl == true
  end

  def perform
    FileUtils.mkdir_p(data_dir)
    puts "PARSING #{crl_url} ..."
    begin
      pp metadata
      write_metadata_to_json
    rescue => e
      puts "... OH, ENCOUNTERED AN ERROR: #{e.class} - #{e.message}"
      write_error_to_json(e)
    end
    puts "-------------------------------"
  end

  def crl
    @crl ||= download_crl
  end

  # note: encountered a "nested asn1 error (OpenSSL::X509::CRLError)" when trying to parse http://sspweb.managed.entrust.com/CRLs/EMSSSPCA2.crl on 3/9/18
  # ... need to investigate further (see https://stackoverflow.com/q/24263835/670433)
  def download_crl
    IO.copy_stream(open(crl_url), crl_filepath) unless File.exist?(crl_filepath) && !overwrite_crl?
    return OpenSSL::X509::CRL::new(File.read(crl_filepath))
  end

  def revocations
    @revocations ||= crl.revoked.sort_by{ |revocation| revocation.try(:time) } # use .try because crl.revoked may be empty
  end

  def metadata
    @metadata ||= {
      issuer: crl.issuer.to_s,
      version: crl.version.to_s,
      last_update: crl.last_update.to_s,
      next_update: crl.next_update.to_s,
      revocations_count: revocations.count,
      earliest_revocation: revocation_metadata(revocations.first),
      latest_revocation: revocation_metadata(revocations.last)
    }
  end

  def revocation_metadata(revoked)
    Revocation.new(revoked).metadata if revoked
  end

  def crl_filename
    crl_url.split("/").last
  end

  def crl_name
    crl_filename.gsub(".crl","")
  end

  def data_dir
    "./data/#{crl_name}/#{Date.today.to_s}"
  end

  def crl_filepath
    File.join(data_dir, crl_filename)
  end

  def metadata_filepath
    File.join(data_dir, "metadata.json")
  end

  def write_metadata_to_json
    File.open(metadata_filepath, "w") do |f|
      f.write(JSON.pretty_generate(metadata))
    end
  end

  def error_filepath
    File.join(data_dir, "errors.json")
  end

  def write_error_to_json(err)
    File.open(error_filepath, "w") do |f|
      f.write(JSON.pretty_generate({error: "#{err.class} - #{err.message}"}))
    end
  end
end

class Revocation
  attr_reader :revoked

  # @param revoked [OpenSSL::X509::Revoked]
  def initialize(revoked)
    @revoked = revoked
  end

  def metadata
    {
      serial_number: revoked.serial.to_s,
      revoked_at: revoked.time.to_s,
      extensions: revoked.extensions.map{ |ext| ext.to_h }
    }
  end
end

crl_urls = []

# DISA/DOD (CAC) CRLs
# this list reflects the contents of an "ALLCRLZIP" file obtained one-time from https://crl.disa.mil/getcrlzip?ALL+CRL+ZIP (which needs certain certs to access via the web)
crl_urls += [
  "http://crl.disa.mil/crl/DMDNSIGNINGCA_1.crl",
  "http://crl.disa.mil/crl/DODCA_31.crl",
  "http://crl.disa.mil/crl/DODCA_32.crl",
  "http://crl.disa.mil/crl/DODEMAILCA_31.crl",
  "http://crl.disa.mil/crl/DODEMAILCA_32.crl",
  "http://crl.disa.mil/crl/DODEMAILCA_33.crl",
  "http://crl.disa.mil/crl/DODEMAILCA_34.crl",
  "http://crl.disa.mil/crl/DODEMAILCA_39.crl",
  "http://crl.disa.mil/crl/DODEMAILCA_40.crl",
  "http://crl.disa.mil/crl/DODEMAILCA_41.crl",
  "http://crl.disa.mil/crl/DODEMAILCA_42.crl",
  "http://crl.disa.mil/crl/DODEMAILCA_43.crl",
  "http://crl.disa.mil/crl/DODEMAILCA_44.crl",
  "http://crl.disa.mil/crl/DODEMAILCA_49.crl",
  "http://crl.disa.mil/crl/DODEMAILCA_50.crl",
  "http://crl.disa.mil/crl/DODEMAILCA_51.crl",
  "http://crl.disa.mil/crl/DODEMAILCA_52.crl",
  "http://crl.disa.mil/crl/DODIDCA_33.crl",
  "http://crl.disa.mil/crl/DODIDCA_34.crl",
  "http://crl.disa.mil/crl/DODIDCA_39.crl",
  "http://crl.disa.mil/crl/DODIDCA_40.crl",
  "http://crl.disa.mil/crl/DODIDCA_41.crl",
  "http://crl.disa.mil/crl/DODIDCA_42.crl",
  "http://crl.disa.mil/crl/DODIDCA_43.crl",
  "http://crl.disa.mil/crl/DODIDCA_44.crl",
  "http://crl.disa.mil/crl/DODIDCA_49.crl",
  "http://crl.disa.mil/crl/DODIDCA_50.crl",
  "http://crl.disa.mil/crl/DODIDCA_51.crl",
  "http://crl.disa.mil/crl/DODIDCA_52.crl",
  "http://crl.disa.mil/crl/DODIDSWCA_35.crl",
  "http://crl.disa.mil/crl/DODIDSWCA_36.crl",
  "http://crl.disa.mil/crl/DODIDSWCA_37.crl",
  "http://crl.disa.mil/crl/DODIDSWCA_38.crl",
  "http://crl.disa.mil/crl/DODIDSWCA_45.crl",
  "http://crl.disa.mil/crl/DODIDSWCA_46.crl",
  "http://crl.disa.mil/crl/DODIDSWCA_47.crl",
  "http://crl.disa.mil/crl/DODIDSWCA_48.crl",
  "http://crl.disa.mil/crl/DODINTEROPERABILITYROOTCA1.crl",
  "http://crl.disa.mil/crl/DODINTEROPERABILITYROOTCA2.crl",
  "http://crl.disa.mil/crl/DODNIPRINTERNALNPEROOTCA1.crl",
  "http://crl.disa.mil/crl/DODNPEROOTCA1.crl",
  "http://crl.disa.mil/crl/DODROOTCA2.crl",
  "http://crl.disa.mil/crl/DODROOTCA3.crl",
  "http://crl.disa.mil/crl/DODROOTCA4.crl",
  "http://crl.disa.mil/crl/DODROOTCA5.crl",
  "http://crl.disa.mil/crl/DODSWCA_53.crl",
  "http://crl.disa.mil/crl/DODSWCA_54.crl",
  "http://crl.disa.mil/crl/DODSWCA_55.crl",
  "http://crl.disa.mil/crl/DODSWCA_56.crl",
  "http://crl.disa.mil/crl/DODSWCA_57.crl",
  "http://crl.disa.mil/crl/DODSWCA_58.crl",
  "http://crl.disa.mil/crl/DODWCFROOTCA1.crl",
  "http://crl.disa.mil/crl/ECAROOTCA2.crl",
  "http://crl.disa.mil/crl/ECAROOTCA4.crl",
  "http://crl.disa.mil/crl/IDENTRUSTECA4.crl",
  "http://crl.disa.mil/crl/IDENTRUSTECA5.crl",
  "http://crl.disa.mil/crl/IDENTRUSTECACOMPONENTS21.crl",
  "http://crl.disa.mil/crl/IDENTRUSTECAS21.crl",
  "http://crl.disa.mil/crl/ORCECA6.crl",
  "http://crl.disa.mil/crl/ORCECAHW5.crl",
  "http://crl.disa.mil/crl/ORCECASW5.crl",
  "http://crl.disa.mil/crl/USDODCCEBINTEROPERABILITYROOTCA1.crl",
  "http://crl.disa.mil/crl/USDODCCEBINTEROPERABILITYROOTCA2.crl"
]

# Entrust (PIV) CRLs
crl_urls << "http://sspweb.managed.entrust.com/CRLs/EMSSSPCA2.crl"

crl_urls.each do |crl_url|
  Parser.new(crl_url: crl_url, overwrite_crl: false).perform
end
