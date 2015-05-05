#!/usr/bin/env ruby

# 
# **author:** R. Nick McCandless
#
# Command line script to download logs from S3 bucket, concatenate them info a file, formats the file, and analyzes it
#
# **Usages**
# `$ ruby aws_s3_logs.rb <bucket_name> <access_key_id> <secret_access_key> <prefix>`
# or
# Hard code the variables @ the top of the file, then `$ ruby aws_s3_logs.rb`
#

# Ruby version check
abort("You're using ruby #{RUBY_VERSION}. Please use version 2.1 or newer") if (RUBY_VERSION.to_f < 2.1)

bucket_name           = ''
access_key_id         = ''
secret_access_key     = ''
prefix                = ''

require 'rubygems'
require 'fileutils'
require 'csv'
require 'json'

# prefix: Subfolder - will create subfolder on local drive similar to prefix
aws_information = {
    bucket_name:       ARGV[0] || bucket_name,
    access_key_id:     ARGV[1] || access_key_id,
    secret_access_key: ARGV[2] || secret_access_key,
    prefix:            ARGV[3] || prefix
}
options = {
    aws_logs_dir: 'aws_s3_logs',
    concat_file:  "#{aws_information[:bucket_name]}.log"
}

if (aws_information.any? { |k, v| !v.empty? })
  puts "\nThe following credentials have been added:"
  aws_information.each { |k, v| puts "#{k}: #{v}" }
else
  puts 'Please check usages - either pass in the S3 credentials in the command line or hard code them in the file.'
  abort "\nNo S3 credentials provided - existing!\n"
end

puts "\n\nWhat would you like to do with the S3 logs? download, concat (or concatenate), format, analyze, or exit"
input1 = $stdin.gets.chomp

begin
  case input1
    when 'download', 'concat', 'concatenate', 'format', 'analyze'
      send(input1, aws_information, options)
    when 'exit', 'quit'
      abort 'Good bye!'
    else
      raise NoMethodError
  end

rescue NoMethodError
  abort 'No function by that name.'
end



BEGIN {

  # Downloads logs from S3
  def download aws_information, options
    puts 'Downloading logs. Please wait a while...'

    begin
      require 'aws-sdk'
    rescue LoadError
      abort 'Unable to load AWS gem. Is the gem `aws-sdk` installed?'
    end

    s3 = Aws::S3::Client.new(
        region: 'us-east-1',
        credentials: Aws::Credentials.new(aws_information[:access_key_id], aws_information[:secret_access_key])
    )
    s3_files = s3.list_objects(bucket: aws_information[:bucket_name], prefix: aws_information[:prefix]).contents

    FileUtils.mkdir_p "./#{options[:aws_logs_dir]}"

    if aws_information[:prefix]
      FileUtils.mkdir_p "./#{options[:aws_logs_dir]}/#{aws_information[:prefix]}"
      s3_files.shift.key # Don't include the folder itself
    end

    s3_files.each do |o|
      resp = s3.get_object(bucket: aws_information[:bucket_name], key: o.key)

      File.open("./aws_s3_logs/#{o.key}.txt", 'w') do |f|
        f.write resp.body.read
      end

      puts "Downloaded log file: #{o.key}"
    end

    puts "\nCompleted...\n"
  end


  # Concatenate all log files into one
  def concatenate aws_information, options
    puts "Concatenating all log files to log file named: #{options[:concat_file]}"

    log_count = Dir[File.join("./#{options[:aws_logs_dir]}/#{aws_information[:prefix]}", '**', '*')].length
    puts "Log count is: #{log_count}"

    if log_count.to_i < 1
      abort("\nNo files to concatenate. Please get the log files from S3\n\n")
    end

    #Clear concat file first
    File.truncate("./#{options[:aws_logs_dir]}/#{options[:concat_file]}", 0) if File.exist?("./#{options[:aws_logs_dir]}/#{options[:concat_file]}")

    # Concatenate log files into one
    Dir.foreach(File.join("./#{options[:aws_logs_dir]}/#{aws_information[:prefix]}")) do |log|
      next if log == '.' or log == '..'
      File.open("./#{options[:aws_logs_dir]}/#{options[:concat_file]}", 'a+') do |f|
        f << File.read("./#{options[:aws_logs_dir]}/#{aws_information[:prefix]}/#{log}")
      end
    end

    puts "\nConcatenate complete.\n"
  end

  (class << self; self; end).send :alias_method, :concat, :concatenate


  # Formats logs
  def format aws_information, options
    puts 'Formatting logs now. Please wait a while...'

    log_count = Dir[File.join("./#{options[:aws_logs_dir]}/#{aws_information[:prefix]}", '**', '*')].length
    puts "Log count is: #{log_count}"

    if log_count.to_i < 1
      abort("\nNo files to concatenate. Please get the log files from S3\n\n")
    end

    unless File.file?("./#{options[:aws_logs_dir]}/#{options[:concat_file]}")
      abort("\nThe concatenated log file ./aws_s3_logs/#{aws_information[:bucket_name]}.log does not exist. Please create this file first.\n\n")
    end

    log_results = concat_to_array_hash "./#{options[:aws_logs_dir]}/#{options[:concat_file]}"

    # To CSV file
    CSV.open("./#{options[:aws_logs_dir]}/#{options[:concat_file]}.csv", 'wb', {force_quotes: true}) do |csv|
      csv << log_results.first.keys
      log_results.each { |l| csv << l.values }
    end

    puts "\nFormat complete.\n"
  end


  # Creates an analysis report to JSON & outputs the results 
  def analyze  aws_information, options
    analytics_results = {}

    log_results = concat_to_array_hash "./#{options[:aws_logs_dir]}/#{options[:concat_file]}", [:ip_address]

    analytics_results[:ip_count] = log_results.each_with_object(Hash.new(0)) { |word,counts| counts[word] += 1 }.sort_by{ |k, v| v }.reverse.to_h.first(100).map{ |v| v }.map { |key, val| {key[:ip_address] => val} }

    puts "\nResults give are the top 100 IP sorted by count"

    # To JSON file
    File.open("./#{options[:aws_logs_dir]}/#{options[:concat_file]}_analysis.json","w") do |f|
      f.write(analytics_results[:ip_count].to_json)
    end

    puts analytics_results[:ip_count].to_json
  end


  private

  def concat_to_array_hash concat_file, options_switch = [:first_hash,:bucket_name,:datetime_stamp,:ip_address,:second_hash,:api_method,:request_data]
    log_results = []

    # Regex for S3 Logs
    regex_options = {
      first_hash:       /[$a-zA-Z0-9]{64}/,
      bucket_name:      /\s[\w]*\.[\w]*\.[\w]{1,}\s/,
      datetime_stamp:   /\[\d{1,2}\/\w{1,10}\/\d{1,4}\:\d{1,2}\:\d{1,2}\:\d{1,2}\s\+\d{1,4}\]/,
      ip_address:       /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/,
      second_hash:      /\s[$A-Z0-9]{16}\s/,
      api_method:       /[A-Z]*\.[A-Z]*\.[A-Z]*/,
      request_data:     /\s\".*$/
    }

    # Reads concatenated file and stores it in an array of hashes
    File.readlines(concat_file).each do |l|
      log_match = Hash.new

      regex_options.keys.each do |k|
        log_match[k] = l.match(regex_options[k]).to_s.strip if options_switch.include?(k)
      end

      log_results << log_match
    end
    log_results
  end

}



# EOD