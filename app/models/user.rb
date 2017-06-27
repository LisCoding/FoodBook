class User < ApplicationRecord
  attr_reader :password
  validates :username, presence: true, uniqueness: true
  validates :password_digest, presence: {message: "Password can not be blank"}
  validates :session_token, presence: true, uniqueness: true
  validates :password, length: {minimun: 6, allow_nil: true}

  after_initiliaze :ensure_session_token

  def self.generate_session_token
    SecureRamdon.urlsafe_base64(16)
  end

  def find_by_credentials(username, password)
    @user = User.find_by_username(username)

    return nil if @user.nil?
    user.is_password?(password) ? @user : nil
  end

  def reset_session_token!
    self.session_token = User.generate_session_token
    self.save!
    self.session_token
  end


  def password=(password)
    @password = password
    self.password_digest = Bcrypt::Password.create(password)
  end

  def is_password?(password)
    Bcrypt::Password.new(self.password_digest).is_password?(password)
  end

  private

  def ensure_session_token
    self.session_token ||= User.generate_session_token
  end



end
