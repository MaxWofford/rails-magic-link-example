class StaticPagesController < ApplicationController
  before_action :authenticate_user!, only: [:about]

  def home
  end

  def about
  end
end
