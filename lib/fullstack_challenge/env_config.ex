defmodule FullstackChallenge.EnvConfig do
  def load_dotenv do
    if File.exists?(".env") do
      case DotenvParser.load_file(".env") do
        :ok ->
          :ok
        {:error, reason} ->
          IO.puts("Warning: Failed to load .env file: #{inspect(reason)}")
          :error
      end
    else
      :ok
    end
  end

  def get_fly_token do
    System.get_env("FLY_API_TOKEN")
  end
end