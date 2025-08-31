defmodule FullstackChallenge.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    unless Mix.env() == :test do
      FullstackChallenge.EnvConfig.load_dotenv()
    end
    
    children = [
      FullstackChallengeWeb.Telemetry,
      FullstackChallenge.Repo,
      {Ecto.Migrator,
       repos: Application.fetch_env!(:fullstack_challenge, :ecto_repos), skip: skip_migrations?()},
      {DNSCluster, query: Application.get_env(:fullstack_challenge, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: FullstackChallenge.PubSub},
      FullstackChallenge.TokenStore,
      FullstackChallengeWeb.Endpoint
    ]

    opts = [strategy: :one_for_one, name: FullstackChallenge.Supervisor]
    Supervisor.start_link(children, opts)
  end

  @impl true
  def config_change(changed, _new, removed) do
    FullstackChallengeWeb.Endpoint.config_change(changed, removed)
    :ok
  end

  defp skip_migrations?() do
    System.get_env("RELEASE_NAME") == nil
  end
end
