Rails.application.routes.draw do
  devise_for :users
  root 'static_pages#home', as: :login
  get '/about', to: 'static_pages#about'

  # For details on the DSL available within this file, see http://guides.rubyonrails.org/routing.html
end
