Rails.application.routes.draw do
  get "/accounts/:account_id/notes/:id", to: "notes#show"
end
