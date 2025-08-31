defmodule FullstackChallenge.TokenSecurity do
  @moduledoc """
  Handles secure token encryption/decryption for session storage
  """

  @encryption_salt "fly_token_salt_2024"

  def encrypt_token(token) when is_binary(token) do
    secret_key_base = get_secret_key_base()
    key = :crypto.hash(:sha256, secret_key_base <> @encryption_salt)
    iv = :crypto.strong_rand_bytes(16)
    
    {encrypted_token, _tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, token, "", true)
    
    Base.encode64(iv <> encrypted_token)
  end

  def decrypt_token(encrypted_data) when is_binary(encrypted_data) do
    try do
      secret_key_base = get_secret_key_base()
      key = :crypto.hash(:sha256, secret_key_base <> @encryption_salt)
      
      decoded = Base.decode64!(encrypted_data)
      <<iv::binary-16, encrypted_token::binary>> = decoded
      
      case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, encrypted_token, "", false) do
        {decrypted_token, ""} -> {:ok, decrypted_token}
        _ -> {:error, :decryption_failed}
      end
    rescue
      _ -> {:error, :invalid_format}
    end
  end

  def decrypt_token(nil), do: {:error, :no_token}

  defp get_secret_key_base do
    Application.get_env(:fullstack_challenge, FullstackChallengeWeb.Endpoint)[:secret_key_base] ||
      raise "secret_key_base not configured"
  end
end