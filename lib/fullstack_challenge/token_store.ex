defmodule FullstackChallenge.TokenStore do
  @moduledoc """
  Secure in-memory token storage using ETS to handle large Fly.io API tokens
  that exceed cookie size limits.
  
  Security features:
  - Protected ETS table (only owner can write)
  - Session binding (tokens tied to session IDs)
  - One-time retrieval option
  - Rate limiting
  - Audit logging
  - Memory limits
  """
  
  use GenServer
  require Logger
  
  @table_name :token_store
  @rate_limit_table :token_store_rate_limit
  @audit_table :token_store_audit
  @ttl_hours 24
  @max_tokens 10_000  # Maximum tokens in memory
  @rate_limit_attempts 50  # Max attempts per minute (increased for development)
  @rate_limit_window 60  # seconds
  
  # Client API
  
  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end
  
  @doc """
  Store a token with session binding and get back a reference ID.
  Returns {:ok, reference_id} or {:error, reason}
  """
  def store_token(token, session_id, ip_address \\ nil) when is_binary(token) do
    GenServer.call(__MODULE__, {:store_token, token, session_id, ip_address})
  end
  
  @doc """
  Retrieve a token by its reference ID with session validation.
  Returns {:ok, token} or {:error, :not_found | :expired | :session_mismatch | :rate_limited}
  """
  def get_token(ref_id, session_id, options \\ []) when is_binary(ref_id) do
    one_time = Keyword.get(options, :one_time, false)
    ip_address = Keyword.get(options, :ip_address)
    
    case check_rate_limit(session_id) do
      :ok ->
        case :ets.lookup(@table_name, ref_id) do
          [{^ref_id, token, expires_at, stored_session_id, metadata}] ->
            cond do
              System.system_time(:second) >= expires_at ->
                delete_token(ref_id)
                log_audit(:expired, ref_id, session_id, ip_address)
                Logger.debug("Token expired and removed")
                {:error, :expired}
              
              stored_session_id != session_id ->
                log_audit(:session_mismatch, ref_id, session_id, ip_address)
                Logger.warning("Token access denied: session mismatch")
                {:error, :session_mismatch}
              
              one_time and Map.get(metadata, :retrieved, false) ->
                log_audit(:already_retrieved, ref_id, session_id, ip_address)
                Logger.warning("Token access denied: already retrieved")
                {:error, :already_retrieved}
              
              true ->
                if one_time do
                  updated_metadata = Map.put(metadata, :retrieved, true)
                  :ets.insert(@table_name, {ref_id, token, expires_at, stored_session_id, updated_metadata})
                end
                
                log_audit(:success, ref_id, session_id, ip_address)
                Logger.debug("Token retrieved successfully")
                {:ok, token}
            end
          
          [] ->
            log_audit(:not_found, ref_id, session_id, ip_address)
            Logger.debug("Token not found")
            {:error, :not_found}
        end
      
      :rate_limited ->
        log_audit(:rate_limited, ref_id, session_id, ip_address)
        Logger.warning("Token access denied: rate limited")
        {:error, :rate_limited}
    end
  end
  
  @doc """
  Delete a token by its reference ID.
  """
  def delete_token(ref_id) when is_binary(ref_id) do
    GenServer.call(__MODULE__, {:delete_token, ref_id})
  end
  
  @doc """
  Clean up expired tokens. Called periodically by GenServer.
  """
  def cleanup_expired() do
    GenServer.cast(__MODULE__, :cleanup_expired)
  end
  
  # Server callbacks
  
  @impl true
  def init(_) do
    :ets.new(@table_name, [:set, :protected, :named_table, read_concurrency: true])
    
    :ets.new(@rate_limit_table, [:set, :public, :named_table])
    
    :ets.new(@audit_table, [:ordered_set, :public, :named_table])
    
    schedule_cleanup()
    
    {:ok, %{token_count: 0}}
  end
  
  @impl true
  def handle_call({:delete_token, ref_id}, _from, state) do
    :ets.delete(@table_name, ref_id)
    hashed_ref = hash_for_logging(ref_id)
    Logger.debug("Deleted token with ref hash: #{hashed_ref}")
    new_count = Enum.max([state.token_count - 1, 0])
    {:reply, :ok, %{state | token_count: new_count}}
  end
  
  @impl true
  def handle_call({:store_token, token, session_id, ip_address}, _from, state) do
    if state.token_count >= @max_tokens do
      Logger.warning("Token store at capacity (#{@max_tokens} tokens)")
      {:reply, {:error, :capacity_exceeded}, state}
    else
      ref_id = generate_ref_id()
      expires_at = System.system_time(:second) + (@ttl_hours * 3600)
      
      metadata = %{
        created_at: System.system_time(:second),
        ip_address: ip_address,
        retrieved: false
      }
      
      :ets.insert(@table_name, {ref_id, token, expires_at, session_id, metadata})
      
      log_audit(:store, ref_id, session_id, ip_address)
      hashed_ref = hash_for_logging(ref_id)
      Logger.info("Stored token with ref hash: #{hashed_ref}")
      
      {:reply, {:ok, ref_id}, %{state | token_count: state.token_count + 1}}
    end
  end
  
  @impl true
  def handle_cast(:cleanup_expired, state) do
    now = System.system_time(:second)
    
    expired = :ets.select(@table_name, [
      {
        {:"$1", :"$2", :"$3", :"$4", :"$5"},
        [{:<, :"$3", now}],
        [:"$1"]
      }
    ])
    
    Enum.each(expired, fn ref_id ->
      :ets.delete(@table_name, ref_id)
      hashed_ref = hash_for_logging(ref_id)
      Logger.debug("Deleted expired token with ref hash: #{hashed_ref}")
    end)
    
    audit_cutoff = now - (7 * 24 * 3600)
    old_audits = :ets.select(@audit_table, [
      {
        {:"$1", :"$2"},
        [{:<, {:element, 1, :"$1"}, audit_cutoff}],
        [:"$1"]
      }
    ])
    Enum.each(old_audits, &:ets.delete(@audit_table, &1))
    
    rate_cutoff = now - @rate_limit_window
    :ets.select_delete(@rate_limit_table, [
      {
        {:"$1", :"$2"},
        [{:<, :"$2", rate_cutoff}],
        [true]
      }
    ])
    
    new_count = :ets.info(@table_name, :size)
    
    if length(expired) > 0 do
      Logger.info("Cleaned up #{length(expired)} expired tokens")
    end
    
    {:noreply, %{state | token_count: new_count}}
  end
  
  @impl true
  def handle_info(:scheduled_cleanup, state) do
    cleanup_expired()
    schedule_cleanup()
    {:noreply, state}
  end
  
  # Private functions
  
  defp generate_ref_id do
    :crypto.strong_rand_bytes(32)
    |> Base.url_encode64(padding: false)
  end
  
  defp schedule_cleanup do
    Process.send_after(self(), :scheduled_cleanup, :timer.hours(1))
  end
  
  defp check_rate_limit(session_id) do
    now = System.system_time(:second)
    cutoff = now - @rate_limit_window
    
    case :ets.lookup(@rate_limit_table, session_id) do
      [{^session_id, timestamps}] ->
        recent = Enum.filter(timestamps, &(&1 > cutoff))
        
        if length(recent) >= @rate_limit_attempts do
          :rate_limited
        else
          :ets.insert(@rate_limit_table, {session_id, [now | recent]})
          :ok
        end
      
      [] ->
        :ets.insert(@rate_limit_table, {session_id, [now]})
        :ok
    end
  end
  
  defp log_audit(action, ref_id, session_id, ip_address) do
    timestamp = System.system_time(:second)
    audit_entry = {
      {timestamp, :erlang.unique_integer()},
      %{
        action: action,
        ref_id: ref_id,
        session_id: session_id,
        ip_address: ip_address,
        timestamp: timestamp
      }
    }
    :ets.insert(@audit_table, audit_entry)
  end
  
  @doc """
  Get audit logs for monitoring.
  """
  def get_audit_logs(limit \\ 100) do
    logs = :ets.tab2list(@audit_table)
    |> Enum.sort_by(&elem(&1, 0), :desc)
    |> Enum.take(limit)
    |> Enum.map(&elem(&1, 1))
    
    {:ok, logs}
  end
  
  @doc """
  Get current token count for monitoring.
  """
  def get_token_count do
    :ets.info(@table_name, :size)
  end
  
  defp hash_for_logging(value) when is_binary(value) do
    :crypto.hash(:sha256, value)
    |> Base.encode16(case: :lower)
    |> String.slice(0, 8)
  end
end
