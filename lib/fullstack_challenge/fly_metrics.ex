defmodule FullstackChallenge.FlyMetrics do
  @moduledoc "Fetch Fly.io metrics via Prometheus API for your dashboard."
  @endpoint "https://api.fly.io/prometheus"
  @timeout 7_000

  @org_slug System.get_env("ORG_SLUG") || "mohamed-a-hameed"
  @token System.get_env("FLY_API_TOKEN") || "YOUR-TOKEN-HERE"

  # List of Prometheus queries per app
  @metrics [
    {"HTTP Responses (by status)", "sum(increase(fly_edge_http_responses_count{app=\"%{app}\"}[5m])) by (status)"},
    {"Memory Usage (%)", "avg((1 - fly_instance_memory_mem_available{app=\"%{app}\"} / fly_instance_memory_mem_total{app=\"%{app}\"}) * 100)"},
    {"CPU Usage", "sum(rate(fly_instance_cpu{app=\"%{app}\",mode!=\"idle\"}[5m]))"}
  ]

  def fetch_for_app(app_name) do
    Enum.map(@metrics, fn {label, query_template} ->
      query = String.replace(query_template, "%{app}", app_name)
      {label, fetch_metric(query)}
    end)
  end

  defp fetch_metric(query) do
    url = "#{@endpoint}/#{@org_slug}/api/v1/query"
    headers = 
  if String.starts_with?(@token, "FlyV1 fm2_") do
    [{"authorization", @token}]
  else
    [{"authorization", "Bearer #{@token}"}]
  end

    params = URI.encode_query(%{"query" => query})
    full_url = "#{url}?#{params}"
    case Req.post(full_url, headers: headers, receive_timeout: @timeout) do
      {:ok, %{status: 200, body: %{"status" => "success", "data" => %{"result" => result}}}} -> {:ok, result}
      {:ok, %{body: %{"error" => reason}}} -> {:error, reason}
      {:error, err} -> {:error, inspect(err)}
      other -> {:error, inspect(other)}
    end
  end
end
