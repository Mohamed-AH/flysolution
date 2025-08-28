defmodule FullstackChallengeWeb.AuthLive do
  use FullstackChallengeWeb, :live_view

  require Logger

  def mount(_params, session, socket) do
    session_id = Map.get(session, "session_id") || generate_session_id()
    
    ip_address = case get_connect_info(socket, :peer_data) do
      %{address: addr} -> format_ip(addr)
      _ -> nil
    end
    
    socket = socket
             |> assign(:session_id, session_id)
             |> assign(:ip_address, ip_address)
    
    session_token = get_token_from_session(session)
    
    env_token = FullstackChallenge.EnvConfig.get_fly_token()

    cond do
      session_token ->
        {:ok, push_navigate(socket, to: ~p"/dashboard")}
      
      env_token ->
        case validate_fly_token(env_token) do
          {:ok, _user_info} ->
            case FullstackChallenge.TokenStore.store_token(env_token, session_id, ip_address) do
              {:ok, ref_id} ->
                {:ok, 
                 socket
                 |> put_flash(:token_ref, ref_id)
                 |> put_flash(:token_source, "env")
                 |> push_navigate(to: ~p"/auth/complete")}
              
              {:error, reason} ->
                {:ok,
                 socket
                 |> assign(:error, "Failed to store environment token: #{reason}")
                 |> assign(:env_file_exists, File.exists?(".env"))}
            end
          
          {:error, reason} ->
            {:ok,
             socket
             |> assign(:error, "Environment token authentication failed: #{reason}")
             |> assign(:env_file_exists, File.exists?(".env"))}
        end
      
      true ->
        {:ok,
         socket
         |> assign(:error, nil)
         |> assign(:env_file_exists, File.exists?(".env"))
         |> assign(:token_form, to_form(%{"token" => ""}, as: :token))}
    end
  end

  def handle_event("refresh", _, socket) do
    FullstackChallenge.EnvConfig.load_dotenv()
    
    env_token = FullstackChallenge.EnvConfig.get_fly_token()

    if env_token do
      case validate_fly_token(env_token) do
        {:ok, _user_info} ->
          session_id = socket.assigns.session_id
          ip_address = socket.assigns.ip_address
          
          case FullstackChallenge.TokenStore.store_token(env_token, session_id, ip_address) do
            {:ok, ref_id} ->
              {:noreply, 
               socket
               |> put_flash(:info, "Token found and validated successfully!")
               |> put_flash(:token_ref, ref_id)
               |> put_flash(:token_source, "env")
               |> push_navigate(to: ~p"/auth/complete")}
            
            {:error, reason} ->
              {:noreply,
               socket
               |> assign(:error, "Failed to store token: #{reason}")
               |> assign(:env_file_exists, File.exists?(".env"))
               |> assign(:token_form, to_form(%{"token" => ""}, as: :token))}
          end
        
        {:error, reason} ->
          {:noreply,
           socket
           |> assign(:error, "Token found but validation failed: #{reason}")
           |> assign(:env_file_exists, File.exists?(".env"))
           |> assign(:token_form, to_form(%{"token" => ""}, as: :token))}
      end
    else
      {:noreply,
       socket
       |> assign(:error, "No FLY_API_TOKEN found in environment. Please check your .env file.")
       |> assign(:env_file_exists, File.exists?(".env"))
       |> assign(:token_form, to_form(%{"token" => ""}, as: :token))}
    end
  end

  def handle_event("validate_token", %{"token" => params}, socket) do
    form = to_form(params, as: :token)
    {:noreply, assign(socket, :token_form, form)}
  end

  def handle_event("submit_token", %{"token" => %{"token" => token}}, socket) do
    cleaned_token = String.trim(token)
    session_id = socket.assigns.session_id
    ip_address = socket.assigns.ip_address
    
    case validate_fly_token(cleaned_token) do
      {:ok, _user_info} ->
        case FullstackChallenge.TokenStore.store_token(cleaned_token, session_id, ip_address) do
          {:ok, ref_id} ->
            {:noreply, 
             socket
             |> put_flash(:info, "Token validated successfully!")
             |> put_flash(:token_ref, ref_id)
             |> push_navigate(to: ~p"/auth/complete")}
          
          {:error, reason} ->
            {:noreply,
             socket
             |> assign(:error, "Token storage failed: #{reason}")
             |> assign(:token_form, to_form(%{"token" => ""}, as: :token))}
        end
      
      {:error, reason} ->
        {:noreply,
         socket
         |> assign(:error, "Token validation failed: #{reason}")
         |> assign(:token_form, to_form(%{"token" => ""}, as: :token))}
    end
  end

  defp validate_fly_token(token) when is_binary(token) and token != "" do
    token = String.trim(token)
    
    unless String.starts_with?(token, "FlyV1") do
      Logger.warning("Invalid token format detected")
      {:error, "Invalid token format - must start with 'FlyV1'"}
    else
      headers = [{"Authorization", "Bearer #{token}"}, {"Content-Type", "application/json"}]
      body = Jason.encode!(%{query: "{ viewer { id email } }"})

      Logger.info("Attempting Fly.io GraphQL authentication")

    case Req.post("https://api.fly.io/graphql", headers: headers, body: body) do
      {:ok, %{status: 200, body: %{"data" => %{"viewer" => %{"id" => _}}}} = _response} ->
        {:ok, "Authenticated"}

      {:ok, %{status: 200, body: %{"errors" => errors}}} ->
        Logger.warning("GraphQL errors from Fly.io API: #{inspect(errors)}")
        {:error, "Invalid token or insufficient permissions"}

      {:ok, %{status: 401}} ->
        Logger.warning("401 Unauthorized from Fly.io API")
        {:error, "Invalid token"}

      {:ok, %{status: status}} ->
        Logger.warning("HTTP error #{status} from Fly.io API")
        {:error, "API error (#{status})"}

      {:error, reason} ->
        Logger.warning("Network error calling Fly.io API: #{inspect(reason)}")
        {:error, "Network error"}
      end
    end
  end

  defp validate_fly_token(_), do: {:error, "Token is required"}
  
  defp get_token_from_session(session) do
    case Map.get(session, "auth_token_ref") do
      ref when is_binary(ref) ->
        session_id = Map.get(session, "session_id") || generate_session_id()
        case FullstackChallenge.TokenStore.get_token(ref, session_id) do
          {:ok, token} -> token
          {:error, _} -> nil
        end
      
      nil ->
        case FullstackChallenge.TokenSecurity.decrypt_token(Map.get(session, "encrypted_fly_token")) do
          {:ok, token} -> token
          _ -> nil
        end
    end
  end
  
  defp generate_session_id do
    :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)
  end
  
  defp format_ip(nil), do: nil
  defp format_ip({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"
  defp format_ip(address) when is_binary(address), do: address
  defp format_ip(_), do: nil
end
