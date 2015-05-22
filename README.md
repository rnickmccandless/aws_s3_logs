__AWS Logs script__  
Command line script to download logs from S3 bucket, concatenate them info a file, format the file, and analyzes it  
  
**Usages**  
`$ ruby aws_s3_logs.rb <bucket_name> <access_key_id> <secret_access_key> <prefix>`  
or  
Hard code the variables @ the top of the file, then `$ ruby aws_s3_logs.rb`  

**Requirements**  
ruby >= 2.1  
gem 'aws-sdk'  
  
**Tested:** only on OSX 10.10  
  
**Author:** R. Nick McCandless  
