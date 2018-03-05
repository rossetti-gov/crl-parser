require "openssl"
require "open-uri"
require "json"
require "csv"
require "pry"
require "active_support/core_ext/object/try"

class Parser
  attr_accessor :crl_url

  def initialize(crl_url)
    @crl_url = crl_url
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
    IO.copy_stream(open(crl_url), crl_filepath) unless File.exist?(crl_filepath)
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
      revocations_count: revocations.count, #> 306926
      earliest_revocation_at: revocations.first.try(:time),
      latest_revocation_at: revocations.last.try(:time)
    }
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

  #def write_revocations_to_json
  #  revs = [] # maybe faster than mapping 300K items in place...
  #  revocations.each do |revocation|
  #    revs << {
  #      serial_number: revocation.serial.to_s,
  #      revoked_at: revocation.time.to_s,
  #      extensions: revocation.extensions.map{ |ext| ext.to_h }
  #    }
  #  end
  #
  #  revocations_filepath = File.join(crl_dir, "revocations.json")
  #  File.open(revocations_filepath ,"w") do |f|
  #    f.write(JSON.pretty_generate(revs)) # is there a way to write incrementally?
  #  end
  #end

  #def write_revocations_to_csv
  #  revocations_filepath = File.join(crl_dir, "revocations.csv")
  #  headers = ["serial_number", "revoked_at", "extensions"]
  #
  #  CSV.open(revocations_filepath, "w", :write_headers=> true, :headers => headers) do |csv|
  #    revocations.each do |revocation|
  #      csv << [
  #        revocation.serial.to_s,
  #        revocation.time.to_s,
  #        revocation.extensions.map{|ext| ext.to_s }.join(" | ") # pipe-delimited string like "CRLReason = Cessation Of Operation | invalidityDate = ..20160610050000Z"
  #      ]
  #    end
  #  end
  #end
end

KNOWN_CRL_URLS = [40, 41, 42, 43, 44, 49, 50, 51, 52].map{ |i|
  "http://crl.disa.mil/crl/DODIDCA_#{i}.crl"
}

KNOWN_CRL_URLS.each do |crl_url|
  Parser.new(crl_url).perform
end
