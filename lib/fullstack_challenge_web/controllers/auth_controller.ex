defmodule FullstackChallengeWeb.AuthController do
  use FullstackChallengeWeb, :controller
  require Logger

  def complete(conn, params) do
    session_id = get_session(conn, "session_id") || generate_session_id()
    conn = put_session(conn, "session_id", session_id)
    
    cond do
      Phoenix.Flash.get(conn.assigns.flash, :token_ref) ->
        ref_id = Phoenix.Flash.get(conn.assigns.flash, :token_ref)
        token_source = Phoenix.Flash.get(conn.assigns.flash, :token_source) || "manual"
        Logger.debug("Authentication completed via flash token reference")
        
        conn
        |> put_session("auth_token_ref", ref_id)
        |> put_session("token_source", token_source)
        |> delete_session("encrypted_fly_token")
        |> delete_session("auth_token")
        |> redirect(to: ~p"/dashboard")
        
      Map.has_key?(params, "ref") ->
        ref_id = params["ref"]
        Logger.debug("Authentication completed via URL token reference")
        
        conn
        |> put_session("auth_token_ref", ref_id)
        |> delete_session("encrypted_fly_token")
        |> delete_session("auth_token")
        |> redirect(to: ~p"/dashboard")
        
      Map.has_key?(params, "token") ->
        encrypted_token = params["token"]
        ip_address = get_client_ip(conn)
        
        env_token = FullstackChallenge.EnvConfig.get_fly_token()
        
        case FullstackChallenge.TokenSecurity.decrypt_token(encrypted_token) do
          {:ok, actual_token} ->
            token_source = if env_token && actual_token == env_token, do: "env", else: "manual"
            
            case FullstackChallenge.TokenStore.store_token(actual_token, session_id, ip_address) do
              {:ok, ref_id} ->
                Logger.debug("Converted encrypted token to secure reference")
                
                conn
                |> put_session("auth_token_ref", ref_id)
                |> put_session("token_source", token_source)
                |> delete_session("encrypted_fly_token")
                |> delete_session("auth_token")
                |> redirect(to: ~p"/dashboard")
              
              {:error, reason} ->
                conn
                |> put_flash(:error, "Token storage failed: #{reason}")
                |> redirect(to: ~p"/auth")
            end
          
          {:error, _reason} ->
            conn
            |> put_flash(:error, "Invalid authentication token")
            |> redirect(to: ~p"/auth")
        end
        
      true ->
        conn
        |> put_flash(:error, "Missing authentication parameters")
        |> redirect(to: ~p"/auth")
    end
  end
  
  def logout(conn, _params) do
    case get_in(conn.assigns, [:auth_token_ref]) || get_session(conn, "auth_token_ref") do
      ref when is_binary(ref) ->
        FullstackChallenge.TokenStore.delete_token(ref)
      _ ->
        nil
    end
    
    conn
    |> clear_session()
    |> put_flash(:info, "Logged out successfully")
    |> redirect(to: ~p"/auth")
  end
  
  defp generate_session_id do
    :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)
  end
  
  defp get_client_ip(conn) do
    case Plug.Conn.get_req_header(conn, "x-forwarded-for") do
      [forwarded_ip | _] ->
        forwarded_ip
        |> String.split(",")
        |> List.first()
        |> String.trim()
      
      [] ->
        case conn.remote_ip do
          {a, b, c, d} -> "#{a}.#{b}.#{c}.#{d}"
          ip when is_binary(ip) -> ip
          _ -> nil
        end
    end
  end
end