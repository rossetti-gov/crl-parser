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

crl_urls = [40, 41, 42, 43, 44, 49, 50, 51, 52].map{ |i|
  "http://crl.disa.mil/crl/DODIDCA_#{i}.crl"
}
crl_urls << "http://sspweb.managed.entrust.com/CRLs/EMSSSPCA2.crl"

crl_urls.each do |crl_url|
  Parser.new(crl_url: crl_url, overwrite_crl: false).perform
end
