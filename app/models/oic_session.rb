class OicSession < ActiveRecord::Base
  unloadable

  before_create :randomize_state!
  before_create :randomize_nonce!

  def self.client_config
    Setting.plugin_redmine_openid_connect
  end

  def client_config
    self.class.client_config
  end

  def self.host_name
    Setting.protocol + "://" + Setting.host_name
  end

  def host_name
    self.class.host_name
  end

  def self.enabled?
    client_config['enabled']
  end

  def self.disabled?
    !self.enabled?
  end

  def self.get_dynamic_config
    hash = Digest::SHA1.hexdigest client_config.to_json
    expiry = client_config['dynamic_config_expiry'] || 86400
    Rails.cache.fetch("oic_session_dynamic_#{hash}", expires_in: expiry) do
      OpenIDConnect::Discovery::Provider::Config.discover!(
        client_config['openid_connect_server_url']
      )
    end
  end

  def self.dynamic_config
    @dynamic_config = get_dynamic_config
  end

  def dynamic_config
    self.class.dynamic_config
  end

  def self.client
    return @client if @client

    if client_config['disable_ssl_validation']
      OpenIDConnect.http_config do |config|
        config.ssl_config.verify_mode = 0
      end
    end

    @client = OpenIDConnect::Client.new(
      identifier: client_config['client_id'],
      secret: client_config['client_secret'],
      redirect_uri: "#{host_name}/oic/local_login",
      authorization_endpoint: dynamic_config.authorization_endpoint,
      token_endpoint: dynamic_config.token_endpoint,
      userinfo_endpoint: dynamic_config.userinfo_endpoint,
      jwks_uri: dynamic_config.jwks_uri,
      end_session_endpoint: dynamic_config.end_session_endpoint,
    )
  end

  def client
    self.class.client
  end

  def self.get_token()
    token = client.access_token!(
      scope: scopes,
      client_auth_method: :basic,
    )
  end

  def get_token()
    self.current_access_token = self.class.get_token()
    self.access_token = current_access_token.access_token if current_access_token.access_token.present?
    self.refresh_token = current_access_token.refresh_token if current_access_token.refresh_token.present?
    self.id_token = current_access_token.id_token if current_access_token.id_token.present?
    self.expires_at = (DateTime.now + current_access_token.expires_in.seconds) if current_access_token.expires_in.present?
    self.save!
    return self.current_access_token
  end

  def current_access_token=(token)
    @current_access_token = token
  end

  def current_access_token
    @current_access_token
  end

  def get_access_token!
    client.authorization_code = code
    response = get_token()
  end

  def refresh_access_token!
    client.refresh_token = refresh_token
    response = get_token()
  end

  def self.parse_token(token)
    jwt = token.split('.')
    return JSON::parse(Base64::decode64(jwt[1]))
  end

  def claims
    if @claims.blank? || id_token_changed?
      @claims = self.class.parse_token(id_token)
    end
    return @claims
  end

  def get_user_info!
    user_info = current_access_token.userinfo!
    user_info.raw_attributes
  end

  def authorized?
    if client_config['group'].blank?
      return true
    end

    return false if !user["member_of"]

    return true if self.admin?

    if client_config['group'].present? &&
       user["member_of"].include?(client_config['group'])
      return true
    end

    return false
  end

  def admin?
    if client_config['admin_group'].present? &&
       user["member_of"].include?(client_config['admin_group'])
      return true
    end

    return false
  end

  def user
    if @user.blank? || id_token_changed?
      @user = JSON::parse(Base64::decode64(id_token.split('.')[1]))
    end
    return @user
  end

  def authorization_url
    client.authorization_uri(
      {
        response_type: :code,
        scope: scopes,
        state: self.state,
        nonce: self.nonce,
      }
    )
  end

  def end_session_url
    return if dynamic_config.end_session_endpoint.nil?
    dynamic_config.end_session_endpoint + "?" + end_session_query.to_param
  end

  def randomize_state!
    self.state = SecureRandom.uuid unless self.state.present?
  end

  def randomize_nonce!
    self.nonce = SecureRandom.uuid unless self.nonce.present?
  end

  def end_session_query
   query = {
     'id_token_hint' => id_token,
     'session_state' => session_state,
     'post_logout_redirect_uri' => "#{host_name}/oic/local_logout",
   }
  end

  def expired?
    self.expires_at.nil? ? false : (self.expires_at < DateTime.now)
  end

  def complete?
    self.access_token.present?
  end

  def scopes
    self.class.scopes
  end

  def self.scopes
    if client_config["scopes"].nil?
      return "openid profile email"
    else
      client_config["scopes"].split(',').each(&:strip).join(' ')
    end
  end

end
