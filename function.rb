# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def is_json (value)
  result = JSON.parse(value)
  result.is_a?(Hash) || result.is_a?(Array)
  return result
rescue JSON::ParserError, TypeError
  return false
end

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
  status_code = nil
  body_content = nil
  header_contents = {}
  event["headers"].keys.map{|content| header_contents[content.downcase] = event["headers"][content]}
  
  if event['httpMethod'] == 'GET'
    if event['path'] == "/"
      if header_contents.keys.include? "authorization" 
        token = header_contents["authorization"][7..-1]
        begin
          decoded_token = JWT.decode token, ENV['JWT_SECRET'], true, { algorithm: 'HS256' }
          decoded_token = decoded_token[0]
        rescue JWT::ImmatureSignature, JWT::ExpiredSignature
          return response(status: 401)
        rescue StandardError
          return response(status: 403)
        end
        return response(body: decoded_token["data"], status: 200)
      else
        return response(status: 403)
      end
    elsif event['path'] == "/token"
      status_code = 405
      return response(body: nil , status: status_code)
    else 
      status_code = 404
      return response(body: nil , status: status_code)
    end
  elsif event['httpMethod'] == 'POST' and event['path'] == "/token"
    if !is_json (event['body'])
      status_code = 422
      return response(body: nil , status: status_code)
    end
    if header_contents['content-type'] == 'application/json'
      payload = {data: JSON.parse(event['body']), exp: Time.now.to_i + 5,nbf: Time.now.to_i + 2}
      status_code = 201
      generated_jwt = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
      return response(body: {"token":generated_jwt } , status: status_code)
    elsif header_contents['content-type'] != 'application/json'
      status_code = 415
      return response(body: nil , status: status_code)
    else
      status_code = 404
      return response(body: nil , status: status_code)
    end
  else
    status_code = 405
    return response(body: nil , status: status_code)
  end
end

def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = 'NOTASECRET'

  # Call /token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/token'
             })

  # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 1,
    nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # Call /
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
end
