class ApiApplicationsController < ChinoBaseController
    before_filter :find_app, only: [:show, :update]
    
before_filter only: :create do
    unless @json.has_key?('application') && @json['application'].responds_to?(:[]) && @json['application']['app_id']
    render nothing: true, status: :bad_request
end
end

before_filter only: :update do
    unless @json.has_key?('application')
        render nothing: true, status: :bad_request
    end
end

before_filter only: :create do
    @app = Application.find_by_name(@json['application']['app_id'])
end

def index
    render json: Application.where('app_id = ?', @app.app_id)
end

def show
    render json: @app
end

def create (name, grant_type, redirect_url)
    jQuery.ajax({
                type: 'POST',
                url: '/applications',
                dataType: 'json',
                contentType: 'application/json',
                data: JSON.stringify({ name : name, grant_type: grant_type, redirect_url: redirect_url}),
                success: function(json) { }
                });
end

def update
    @app.assign_attributes(@json['application'])
    if @app.save
        render json: @app
        else
        render nothing: true, status: :bad_request
    end
end

private
def find_app
    @app = Application.find_by_id(params[:app_id)
    render nothing: true, status: :not_found unless @app.present?
end
end
