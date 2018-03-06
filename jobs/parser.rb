require "openssl"
require "open-uri"
require "json"
require "csv"
require "pry"
require "active_support/core_ext/object/try"

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
    pp metadata
    write_metadata_to_json
    puts "-------------------------------"
  end

  def crl
    @crl ||= download_crl
  end

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
