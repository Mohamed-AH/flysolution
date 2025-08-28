defmodule FullstackChallengeWeb.ChatLive do
  use FullstackChallengeWeb, :live_view
  alias FullstackChallenge.TokenStore

  alias FullstackChallenge.Metrics

  @impl true
  def mount(_params, session, socket) do
    session_id = Map.get(session, "session_id") || generate_session_id()
    token_ref = Map.get(session, "auth_token_ref")

    case token_ref && TokenStore.get_token(token_ref, session_id) do
      {:ok, token} ->
        if connected?(socket) do
          :timer.send_interval(30000, :update_metrics)
        end

        metrics = Metrics.get_basic_metrics("example-app")
        analysis = Metrics.analyze_metrics(metrics)

        {:ok,
         socket
         |> assign(:messages, [])
         |> assign(:loading, false)
         |> assign(:error, nil)
         |> assign(:token, token)
         |> assign(:metrics, metrics)
         |> assign(:analysis, analysis)}

      _ ->
        {:ok, redirect(socket, to: ~p"/auth")}
    end
  end

  defp generate_session_id do
    :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)
  end

  @impl true
  def handle_info(:update_metrics, socket) do
    try do
      metrics = Metrics.get_basic_metrics("example-app")
      analysis = Metrics.analyze_metrics(metrics)
      {:noreply,
       socket
       |> assign(:metrics, metrics)
       |> assign(:analysis, analysis)
       |> put_flash(:info, "Metrics updated successfully")}
    rescue
      e in RuntimeError ->
        {:noreply,
         socket
         |> put_flash(:error, "Failed to update metrics: #{e.message}")
         |> assign(:error, e.message)}
    end
  end

  @impl true
  def handle_event("send_message", %{"message" => message}, socket) do
    messages = socket.assigns.messages ++ [%{text: message, sender: "user", timestamp: DateTime.utc_now()}]
    {:noreply, assign(socket, :messages, messages)}
  end

  @impl true
  def handle_event("clear_messages", _params, socket) do
    {:noreply, assign(socket, :messages, [])}
  end
end