require 'protected_attributes'
require_relative '../helpers/model_helper'

# User class for application
class User < ActiveRecord::Base
  include ModelHelper

  validates :username, presence: true, uniqueness: true
  validates :email, presence: true, uniqueness: true, format: /@/
  validates :hashed_password, presence: true
  # validates :encrytped_address, presence: true
  # validates :encrypted_fullname, presence: true
  # validates :encrypted_dob, presence: true

  attr_accessible :username, :email

  def enc
    enc = RbNaCl::SecretBox.new(key)
    @nonce = enc64(RbNaCl::Random.random_bytes(enc.nonce_bytes)) unless @nonce
    self.nonce = @nonce
    enc
  end

  def dec
    RbNaCl::SecretBox.new(key)
  end

  def dob=(params)
    self.encrypted_dob = enc64(enc.encrypt(dec64(nonce), "#{params}"))
  end

  def dob
    dec.decrypt(dec64(nonce), dec64(encrypted_dob))
  end

  def address=(params)
    self.encrytped_address = enc64(enc.encrypt(dec64(nonce), "#{params}"))
  end

  def address
    dec.decrypt(dec64(nonce), dec64(encrytped_address))
  end

  def fullname=(params)
    self.encrypted_fullname = enc64(enc.encrypt(dec64(nonce), "#{params}"))
  end

  def fullname
    dec.decrypt(dec64(nonce), dec64(encrypted_fullname))
  end

  def password=(new_password)
    salt = RbNaCl::Random.random_bytes(RbNaCl::PasswordHash::SCrypt::SALTBYTES)
    digest = self.class.hash_password(salt, new_password)
    self.salt = enc64(salt)
    self.hashed_password = enc64(digest)
  end

  def self.authenticate!(username, login_password)
    user = User.find_by_username(username)
    user && user.password_matches?(login_password) ? user : nil
  end

  def password_matches?(try_password)
    salt = dec64(self.salt)
    attempted_password = self.class.hash_password(salt, try_password)
    hashed_password == enc64(attempted_password)
  end

  def self.hash_password(salt, pwd)
    opslimit = 2**20
    memlimit = 2**24
    RbNaCl::PasswordHash.scrypt(pwd, salt, opslimit, memlimit)
  end

  # returns all user information as single string
  def to_s
    {
      fullname: fullname,
      address: address,
      dob: dob,
      email: email,
      username: username
    }.to_json
  end
end
