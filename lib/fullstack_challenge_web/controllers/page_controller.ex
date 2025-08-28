defmodule FullstackChallengeWeb.PageController do
  use FullstackChallengeWeb, :controller

  def home(conn, _params) do
    render(conn, :home)
  end
end
