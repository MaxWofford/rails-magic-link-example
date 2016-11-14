class ApplicationController < ActionController::Base
  before_action :authenticate_user!
  protect_from_forgery with: :exception

  protected

  def authenticate_user!
    return if current_user
    maybe_login_from_token unless params[:token].blank?
    if user_signed_in?
      redirect_to request.path, params.except(:token, :action, :controller)
    elsif params[:controller] == 'static_pages' and params[:action] == 'home'
      return
    else
      redirect_to login_path, notice: "Invalid magic link"
    end
  end

  def maybe_login_from_token
    token = params[:token]
    Rails.logger.info "maybe_login_from_token: '#{ token }'"

    if (user = User.find_by_token(token))
      Rails.logger.info "One time login token used for user #{ user.id }"
      sign_in user
      user.new_token!
    else
      Rails.logger.info "No user found from token: '#{ token }'"
    end
  end
end
