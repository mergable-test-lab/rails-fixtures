class NotesController < ActionController::API
  rescue_from ActiveRecord::RecordNotFound do
    render json: { error: "not_found" }, status: :not_found
  end

  def show
    note = Account.find(params[:account_id]).note(params[:id])
    render json: { title: note.title }
  end
end
