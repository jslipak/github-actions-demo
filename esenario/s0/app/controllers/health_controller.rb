class HealthController < ApplicationController
  def show
    render json: { status: 'ok', scenario: 'S0', framework: 'Ruby on Rails' }
  end
end
