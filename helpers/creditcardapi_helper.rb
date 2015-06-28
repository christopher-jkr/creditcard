require 'base64'
require 'rbnacl/libsodium'
require 'jwt'
require 'pony'
require 'openssl'
require 'httparty'
require_relative './model_helper'

# Helper module for CreditCardAPI class
module CreditCardHelper
  include ModelHelper

  API_URL = 'https://appropriate-credit1card2api3.herokuapp.com/api/v1/'
  # API_URL = 'http://127.0.0.1:9393/api/v1/'

  # Class for User Registration
  class Registration
    attr_accessor :username, :password, :email, :dob, :address, :fullname

    def initialize(user_data)
      user_data.each do |k, _|
        instance_variable_set("@#{k}", user_data[k])
      end
    end

    def complete?
      list = instance_variables.map { |var| instance_variable_get var }
      list.all? do |var|
        var && var.strip.length > 0
      end
    end
  end

  def git_reg(login, email)
    new_user = User.new(username: login, email: email)
    new_user.password = enc64(RbNaCl::Random.random_bytes(20))
    new_user
  end

  def git_jwt(login, email)
    payload = { login: login, email: email }
    JWT.encode payload, ENV['MSG_KEY'], 'HS256'
  end

  def git_jwt_dec(jwt)
    decoded_jwt = JWT.decode jwt, ENV['MSG_KEY'], true
    decoded_jwt.first
  end

  def user_jwt
    jwt_payload = {
      'iss' => 'https://appropriate-credit1card2api3.herokuapp.com/',
      'sub' => @current_user.id
    }
    jwt_key = OpenSSL::PKey::RSA.new(ENV['UI_PRIVATE_KEY'])
    JWT.encode jwt_payload, jwt_key, 'RS256'
  end

  def api_register_card(owner, expiration_date, credit_network, number)
    url = API_URL + 'credit_card'
    body_json = { owner: owner, expiration_date: expiration_date,
                  credit_network: credit_network, number: number }.to_json
    headers = { 'authorization' => ('Bearer ' + user_jwt) }
    HTTParty.post url, body: body_json, headers: headers
  end

  def api_retrieve_card
    url = API_URL + 'credit_card?user_id=RQST'
    headers = { 'authorization' => ('Bearer ' + user_jwt) }
    HTTParty.get url, headers: headers
  end

  def api_validate_card(number)
    url = API_URL + "credit_card/validate?number=#{number}"
    headers = { 'authorization' => ('Bearer ' + user_jwt) }
    HTTParty.get url, headers: headers
  end

  def login_user(user)
    payload = { user_id: user.id }
    token = JWT.encode payload, ENV['MSG_KEY'], 'HS256'
    session[:auth_token] = token
    redirect '/'
  end

  def find_user_by_token(token)
    return nil unless token
    decoded_token = JWT.decode token, ENV['MSG_KEY'], true
    payload = decoded_token.first
    logger.info "PAYLOAD: #{payload}"
    User.find_by_id(payload['user_id'])
  end

  def email_registration_verification(registration)
    payload = create_payload(registration)
    fail repeat_data(registration) unless repeat_data(registration) == ' '
    token = JWT.encode payload, ENV['MSG_KEY'], 'HS256'
    enc_msg = encrypt_message(token)
    Pony.mail(to: registration.email,
              subject: 'Your CreditCardAPI Account is Ready.',
              html_body: registration_email(enc_msg))
  end

  def create_payload(registration)
    payload = {}
    registration.instance_variables.map do |e|
      payload["#{e}".gsub('@', '')] = registration.instance_variable_get e
    end
    payload
  end

  def repeat_data(registration)
    rep_username = 'This username is taken.'
    rep_email = 'This email is already associated with an account.'
    rep_username = '' unless User.find_by_username(registration.username)
    rep_email = '' unless User.find_by_email(registration.email)
    "#{rep_username} #{rep_email}"
  end

  def registration_error_msg(e)
    rep_username = 'This username is taken.'
    rep_email = 'This email is already associated with an account.'
    if [rep_username, rep_email].any? { |t| "#{e}".include? t }
      "#{e}"
    else
      'Check email address.'
    end
  end

  def registration_email(enc_msg)
    verification_url = "#{request.base_url}/register?token=#{enc_msg}"
    '<H1>CreditCardAPI Registration Received</H1>'\
    "<p>Please <a href=\"#{verification_url}\">click here</a> to validate "\
    'your email and activate your account.</p>'
  end

  def encrypt_message(token)
    key = Base64.urlsafe_decode64(ENV['MSG_KEY'])
    secret_box = RbNaCl::SecretBox.new(key)
    nonce = RbNaCl::Random.random_bytes(secret_box.nonce_bytes)
    nonce_s = Base64.urlsafe_encode64(nonce)
    enc_token = Base64.urlsafe_encode64(secret_box.encrypt(nonce, token))
    Base64.urlsafe_encode64({ 'message' => enc_token,
                              'nonce' => nonce_s }.to_json)
  end

  def decrypt_message(enc_msg)
    key = Base64.urlsafe_decode64(ENV['MSG_KEY'])
    secret_box = RbNaCl::SecretBox.new(key)
    msg_json = JSON.parse(Base64.urlsafe_decode64(enc_msg))
    nonce = Base64.urlsafe_decode64(msg_json['nonce'])
    msg = Base64.urlsafe_decode64(msg_json['message'])
    secret_box.decrypt(nonce, msg)
  rescue
    raise 'INVALID ENCRYPTED MESSAGE'
  end

  def create_account_with_registration(registration)
    new_user = User.new(username: registration.username,
                        email: registration.email)
    new_user.password = registration.password
    new_user.dob = registration.dob
    new_user.address = registration.address
    new_user.fullname = registration.fullname
    new_user.save ? login_user(new_user) : fail('Could not create new user')
  end

  def create_account_with_enc_token(enc_msg)
    token = decrypt_message(enc_msg)
    payload = (JWT.decode token, ENV['MSG_KEY']).first
    reg = Registration.new(payload)
    create_account_with_registration(reg)
  end
end
