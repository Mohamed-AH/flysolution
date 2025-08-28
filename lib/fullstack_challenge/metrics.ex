defmodule FullstackChallenge.Metrics do
  @moduledoc """
  Module for interacting with Fly.io metrics API.
  """

  @doc """
  Fetches basic metrics for an app.
  Returns CPU usage, memory usage, and request count.
  """
  def get_basic_metrics(app_name) do
    # TODO: Implement actual API call
    # For MVP, return mock data
    %{
      cpu_usage: "25%",
      memory_usage: "128MB",
      request_count: "150/min",
      timestamp: DateTime.utc_now()
    }
  end

  @doc """
  Analyzes metrics to detect potential issues.
  Returns a list of observations.
  """
  def analyze_metrics(metrics) do
    # TODO: Implement actual analysis
    # For MVP, return basic observations
    [
      "CPU usage is normal",
      "Memory usage is within expected range",
      "Request rate is stable"
    ]
  end
end