require 'sinatra'
require 'rack-flash'
require 'sinatra/param'
require_relative './model/user'
require 'config_env'
require_relative './helpers/creditcardapi_helper'
require 'rack/ssl-enforcer'
require 'dalli'

configure :development, :test do
  require 'hirb'
  ConfigEnv.path_to_config("#{__dir__}/config/config_env.rb")
  Hirb.enable
end

# Old CLIs now on Web
class CreditCardAPI < Sinatra::Base
  include CreditCardHelper
  enable :logging

  configure :production do
    use Rack::SslEnforcer
    set :session_secret, ENV['MSG_KEY']
  end

  configure do
    use Rack::Session::Cookie, secret: settings.session_secret
    use Rack::Flash, sweep: true

    set :ops_cache,
        Dalli::Client.new((ENV['MEMCACHIER_SERVERS'] || '').split(','),
                          username: ENV['MEMCACHIER_USERNAME'],
                          password: ENV['MEMCACHIER_PASSWORD'],
                          socket_timeout: 1.5,
                          socket_failure_delay: 0.2
                         )
  end

  helpers Sinatra::Param

  register do
    def auth(*types)
      condition do
        if (types.include? :user) && !@current_user
          session[:redirect] = request.env['REQUEST_URI']
          flash[:error] = 'You must be logged in to view that page'
          redirect '/login'
        end
      end
    end
  end

  before do
    @current_user = find_user_by_token(session[:auth_token])
  end

  get '/login' do
    haml :login
  end

  post '/login' do
    username = params[:username]
    password = params[:password]
    user = User.authenticate!(username, password)
    if user
      login_user(user)
    else
      flash[:error] = 'Exists, does not this account'
      redirect '/login'
    end
  end

  get '/callback' do
    result = HTTParty.post(
      'https://github.com/login/oauth/access_token',
      body: { client_id: ENV['CLIENT_ID'], code: params['code'],
              client_secret: ENV['CLIENT_SECRET'] },
      headers: { 'Accept' => 'application/json' }
    )
    ind, links = Float, ['', '/emails']
    a, b = git_get_info(links, result['access_token'])
    b.each_with_index do |email, idx|
      ind = idx if email['primary'] == true && email['verified'] == true
    end
    if ind.class == Class
      flash[:error] = 'Please verify your github primary email address!'
      return redirect '/login'
    end
    login, email = a['login'], b[ind]['email']
    if User.find_by_email(email)
      user = User.find_by_email(email)
      return login_user(user)
    end
    jwt = git_jwt(email)
    git_user = git_reg(login, email)
    git_repeat(git_user, login, jwt)
  end

  post '/new_username' do
    # TODO: Add error message in case of JWT change
    if params['n_user'] && params['jwt']
      n_user, jwt = params['n_user'], params['jwt']
      payload = git_jwt_dec(jwt)
      git_user = git_reg(n_user, payload['email'])
      git_repeat(git_user, n_user, jwt)
    end
  end

  get '/logout' do
    session[:auth_token] = nil
    flash[:notice] = 'You have logged out'
    redirect '/'
  end

  get '/register' do
    if params[:token]
      token = params[:token]
      begin
        create_account_with_enc_token(token)
        flash[:notice] = 'Welcome! Your account has been created'
      rescue => e
        logger.error "FAIL Return: #{e}"
        flash[:error] = 'Your account could not be created. Your link has '\
        'expired or is invalid'
      end
      redirect '/'
    else
      haml :register
    end
  end

  post '/register' do
    registration = Registration.new(params)

    if (registration.complete?) &&
       (params[:password] == params[:password_confirm])
      begin
        email_registration_verification(registration)
        flash[:notice] = 'Verification link sent to your email. Please check '\
        'your email'
        redirect '/'
      rescue => e
        logger.error "FAIL EMAIL: #{e}"
        msg = registration_error_msg(e)
        flash[:error] = "Could not send registration verification link: #{msg}"
        redirect '/register'
      end
    else
      flash[:error] = 'Please fill in all the fields and ensure passwords match'
      redirect '/register'
    end
  end

  get '/' do
    result = memcache_fetch if @current_user
    haml :index, locals: { result: result }
  end

  get '/user/:username', auth: [:user] do
    username = params[:username]
    unless username == @current_user.username
      flash[:error] = 'You may only look at your own profile'
      redirect '/'
    end

    haml :profile
  end

  get '/services/?', auth: [:user] do
    haml :services
  end

  get '/credit_card/validate/?', auth: [:user] do
    logger.info('VALIDATE')
    if params[:number]
      begin
        number = params[:number]
        save = api_validate_card(number)
        haml :validate, locals: { result: save.body }
      rescue
        logger.error(e)
        halt 410
      end
    else
      haml :validate, locals: { result: '' }
    end
  end

  get '/credit_card/?', auth: [:user] do
    haml :card_make
  end

  post '/credit_card/?', auth: [:user] do
    begin
      number = params[:number]
      credit_network = params[:credit_network]
      expiration_date = params[:expiration_date]
      owner = params[:owner]
      save = api_register_card(owner, expiration_date, credit_network, number)
      if save.code == 201
        flash[:notice] = 'Successfully created...'
      else
        flash[:error] = 'Please check the card number'
      end
      redirect '/services'
    rescue => e
      logger.error(e)
      halt 410
    end
  end

  get '/credit_card/all/?', auth: [:user] do
    begin
      result = memcache_fetch
      haml :my_cards, locals: { result: result }
    rescue => e
      logger.error(e)
      halt 410
    end
  end
end
