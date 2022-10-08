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
  event['headers'].keys.each do |content|
    header_contents[content] = event['headers'][content]
  end
  if event['httpMethod'] == 'GET' and event['path'] == "/"
    auth_content = header_contents['Authorization'].split(" ")
    token = auth_content[1]
    # Responds 403 if a proper Authorization: Bearer <TOKEN> header is not provided
    if auth_content[0] != "Bearer"
      status_code = 403
      body_content = nil
      return response(body: body_content , status: status_code)
    else 
      begin
        decoded_token = JWT.decode token, ENV['JWT_SECRET'], true, { algorithm: 'HS256' }
        body_content =  decoded_token[0]["data"] 
        status_code = 200
        return response(body: body_content , status: status_code)
      rescue JWT::ExpiredSignature, JWT::ImmatureSignature
        status_code = 401
        body_content = nil
        return response(body: body_content , status: status_code)
      end
    end
  elsif event['path'] == "/token"
    if event['httpMethod'] == 'POST'
      if event['body'] == nil
        return response(body: nil , status: 422)
      end
      payload = {}
      if event['headers'].keys.include? "Content-Type" and   header_contents['Content-Type'] != 'application/json' 
        status_code = 415
        return response(body: nil , status: status_code)
      else
        if !is_json (event['body'])
          status_code = 422
          return response(body: nil , status: status_code)
        #elsif event['body'] = '{}'
        # status_code = 201
        # return response(body: body_content , status: status_code)
        else
          payload["data"] = JSON.parse(event['body'])
          payload["nbf"] = Time.now.to_i + 2
          payload["exp"] = Time.now.to_i + 5
          payload = {data: payload, exp: Time.now.to_i + 5, nbf: Time.now.to_i + 2}
          status_code = 201
          generated_jwt = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
          body_content = {"token" => generated_jwt}
          return response(body: body_content , status: status_code)
        end
      end
    else
      status_code = 405
      return response(body: nil , status: status_code)
    end
  else
    status_code = 404
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
