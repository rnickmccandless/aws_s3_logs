#!/usr/bin/env ruby

require 'rubygems'
require 'fileutils'
require 'csv'
require 'json'

aws_information = {
    prefix:             '', # Subfolder - will create subfolder on local drive similar to prefix
    bucket_name:        '',
    access_key_id:      '',
    secret_access_key:  ''
}
options = {
    aws_logs_dir: 'aws_s3_logs',
    concat_file:  "#{aws_information[:bucket_name]}.log"
}

puts 'What would you like to do with the S3 logs? download, concat, format, analyze, or exit'
input1 = gets.chomp

begin
  case input1
    when 'download', 'concat', 'format', 'analyze'
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
      abort 'Unable to load AWS gem. Is the gem install?'
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
      # puts resp.body.read

      puts "Downloaded log file: #{o.key}"
    end

    puts "\nCompleted...\n"
  end


  # Concatenate all log files into one
  def concat aws_information, options
    puts "Concatenating all log files to log file named: #{options[:concat_file]}"

    log_count = Dir[File.join("./#{options[:aws_logs_dir]}/#{aws_information[:prefix]}", '**', '*')].length
    puts "Log count is: #{log_count}"

    if log_count.to_i < 1
      abort("\nNo files to concatenate. Please get the log files from S3\n\n")
    end

    #Clear concat file first
    File.truncate("./#{options[:aws_logs_dir]}/#{options[:concat_file]}", 0)

    # Concatenate log files into one
    Dir.foreach(File.join("./#{options[:aws_logs_dir]}/#{aws_information[:prefix]}")) do |log|
      next if log == '.' or log == '..'
      File.open("./#{options[:aws_logs_dir]}/#{options[:concat_file]}", 'a+') do |f|
        f << File.read("./#{options[:aws_logs_dir]}/#{aws_information[:prefix]}/#{log}")
      end
    end

  end


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

  end


  # Creates an analysis report
  def analyze  aws_information, options
    analytics_results = {}

    log_results = concat_to_array_hash "./#{options[:aws_logs_dir]}/#{options[:concat_file]}", [:ip_address]

    analytics_results[:ip_count] = log_results.each_with_object(Hash.new(0)) { |word,counts| counts[word] += 1 }.sort_by{ |k, v| v }.reverse.to_h.first(100).map{ |v| v }.map { |key, val| {key[:ip_address] => val} }

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



at_exit {
  puts "\n"
}


# EOD