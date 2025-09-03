defmodule FullstackChallengeWeb.DashboardLive do
  use FullstackChallengeWeb, :live_view
  alias FullstackChallenge.FlyMetrics
  require Logger

  def mount(_params, session, socket) do
    fly_token = get_token_from_session(session)
    env_token = FullstackChallenge.EnvConfig.get_fly_token()
    is_env_token = env_token && fly_token && env_token == fly_token

    # Discord-style chat demo apps/messages
    discord_demo_apps = [
      %{id: "web-app-prod", name: "phoenix-web-app", status: "healthy", type: "web"},
      %{id: "api-backend", name: "elixir-api", status: "warning", type: "api"},
      %{id: "worker-service", name: "genserver-workers", status: "error", type: "worker"}
    ]
    discord_demo_messages = %{
      "web-app-prod" => [
        %{type: :ai, content: "Hi! I'm your monitoring assistant for **Phoenix Web App**. Everything looks healthy! 🟢", timestamp: timestamp_now()}
      ],
      "api-backend" => [
        %{type: :ai, content: "⚠️ **Performance Alert**\n\nYour Elixir API is showing elevated response times.", timestamp: timestamp_now()}
      ],
      "worker-service" => [
        %{type: :ai, content: "🔴 **Critical Alert**\n\nGenServer Workers are crashing frequently.", timestamp: timestamp_now()}
      ]
    }

    if fly_token do
      {:ok,
       socket
       |> assign(:fly_token, fly_token)
       |> assign(:is_env_token, is_env_token)
       |> assign(:apps, [])
       |> assign(:loading, true)
       |> assign(:error, nil)
       |> assign(:app_metrics, %{})
       |> assign(:async_tasks, %{})
       |> assign(:metrics_loading, %{})
       |> assign(:show_launch_modal, false)
       |> assign(:show_destroy_modal, false)
       |> assign(:destroy_app, nil)
       |> assign(:launch_form, to_form(%{"name" => ""}, as: :launch))
       |> assign(:discord_apps, discord_demo_apps)
       |> assign(:selected_app, nil)
       |> assign(:messages, discord_demo_messages)
       |> assign(:typing_message, "")
       |> assign(:is_typing, false)
       |> assign(:app_search_query, "")
       |> assign(:filtered_apps, [])
       |> assign(:logs, %{})
       |> assign(:logs_loading, false)
       |> assign(:log_streams, %{})
       |> load_apps()}
    else
      {:ok, push_navigate(socket, to: ~p"/auth")}
    end
  end

  #########################
  #   FLY.IO APP EVENTS   #
  #########################
  def handle_event("load_apps", _, socket) do
    {:noreply, socket |> assign(:loading, true) |> load_apps()}
  end

  def handle_event("show_launch_modal", _, socket) do
    {:noreply,
     socket
     |> assign(:show_launch_modal, true)
     |> assign(:launch_form, to_form(%{"name" => ""}, as: :launch))}
  end

  def handle_event("hide_launch_modal", _, socket) do
    {:noreply, assign(socket, :show_launch_modal, false)}
  end

  def handle_event("validate_launch", %{"launch" => params}, socket) do
    form = to_form(params, as: :launch)
    {:noreply, assign(socket, :launch_form, form)}
  end

  def handle_event("launch_app", %{"launch" => %{"name" => name}}, socket) do
    case launch_app(socket.assigns.fly_token, name) do
      {:ok, _result} ->
        {:noreply,
         socket
         |> assign(:show_launch_modal, false)
         |> put_flash(:info, "App '#{name}' launched successfully!")
         |> load_apps()}
      {:error, reason} ->
        {:noreply,
         socket
         |> put_flash(:error, "Failed to launch app: #{reason}")}
    end
  end

  def handle_event("show_destroy_modal", %{"app" => app_name}, socket) do
    {:noreply,
     socket
     |> assign(:show_destroy_modal, true)
     |> assign(:destroy_app, app_name)}
  end

  def handle_event("hide_destroy_modal", _, socket) do
    {:noreply,
     socket
     |> assign(:show_destroy_modal, false)
     |> assign(:destroy_app, nil)}
  end

  def handle_event("destroy_app", _, socket) do
    app_name = socket.assigns.destroy_app
    Logger.info("Starting destroy for app: #{app_name}")
    case destroy_app(socket.assigns.fly_token, app_name) do
      {:ok, _result} ->
        Logger.info("App #{app_name} destroyed successfully")
        {:noreply,
         socket
         |> assign(:show_destroy_modal, false)
         |> assign(:destroy_app, nil)
         |> put_flash(:info, "App '#{app_name}' destroyed successfully!")
         |> load_apps()}
      {:error, reason} ->
        Logger.warning("Failed to destroy app #{app_name}: #{reason}")
        {:noreply,
         socket
         |> assign(:show_destroy_modal, false)
         |> assign(:destroy_app, nil)
         |> put_flash(:error, "Failed to destroy app: #{reason}")}
    end
  end
  
  def handle_event("update_app_search", %{"search" => %{"query" => query}}, socket) do
    filtered_apps = filter_apps(socket.assigns.apps, query)
    
    {:noreply, 
    socket
    |> assign(:app_search_query, query)
    |> assign(:filtered_apps, filtered_apps)}
  end

  def handle_event("clear_app_search", _, socket) do
    {:noreply, 
    socket
    |> assign(:app_search_query, "")
    |> assign(:filtered_apps, socket.assigns.apps)}
  end

  # Add the filtering function:

  defp filter_apps(apps, query) when is_binary(query) do
    if String.trim(query) == "" do
      apps
    else
      query_lower = String.downcase(String.trim(query))
      Enum.filter(apps, fn app ->
        app.name |> String.downcase() |> String.contains?(query_lower) ||
        app.id |> String.downcase() |> String.contains?(query_lower)
      end)
    end
  end

  defp filter_apps(apps, _), do: apps 
  #########################################
  #  OPTIMIZED APP SELECTION HANDLERS    #
  #########################################
  def handle_event("select_app", %{"app" => app_id}, socket) do
    # Instant app switching - no blocking operations
    socket =
      socket
      |> assign(:selected_app, app_id)
      |> async_fetch_metrics_for_app(app_id)

    {:noreply, socket}
  end

  def handle_event("update_typing", %{"typing_message" => val}, socket) do
    {:noreply, assign(socket, typing_message: val)}
  end

def handle_event("send_message", _params, socket) do
  Logger.info("[Chat Debug] send_message event triggered!")
  app_id = socket.assigns.selected_app
  msg = (socket.assigns.typing_message || "") |> String.trim()
  
  Logger.info("[Chat Debug] Sending message: #{inspect(msg)} to app: #{inspect(app_id)}")
  
  if msg == "" or is_nil(app_id) do
    Logger.info("[Chat Debug] Message empty or app not found, skipping AI call.")
    {:noreply, socket}
  else
    # Find the actual app from either real apps or discord demo apps
    app = Enum.find(socket.assigns.apps, &(&1.id == app_id)) || 
          Enum.find(socket.assigns.discord_apps, &(&1.id == app_id))
    
    if is_nil(app) do
      Logger.warning("[Chat Debug] No app found for ID: #{app_id}")
      {:noreply, socket}
    else
      user_msg = %{
        type: :user,
        content: msg,
        timestamp: timestamp_now()
      }
      
      updated_messages = Map.update(socket.assigns.messages, app_id, [user_msg], &(&1 ++ [user_msg]))
      socket = socket |> assign(messages: updated_messages, typing_message: "", is_typing: true)
      
      # Build comprehensive context for AI
      app_context = build_app_context(app, socket.assigns.app_metrics[app_id], socket.assigns.logs[app_id])
      
      # Get conversation history
      recent_messages = updated_messages[app_id] |> Enum.take(-6)
      
      self_pid = self()
      
      Task.start(fn ->
        try do
          Logger.info("[Chat Debug] Task started for AI reply with enhanced context")
          ai_reply =
            case openrouter_chat_api(app_context, recent_messages) do
              {:ok, reply} -> reply
              {:error, reason} -> 
                Logger.error("[Chat Debug] OpenRouter API error: #{reason}")
                "I'm having trouble connecting to my AI service right now. Error: #{reason}"
            end
          
          ai_msg = %{
            type: :ai,
            content: ai_reply,
            timestamp: timestamp_now()
          }
          
          Logger.info("[Chat Debug] Sending bot_reply: #{inspect(ai_msg)}")
          send(self_pid, {:bot_reply, ai_msg, app_id})
        rescue
          err -> 
            Logger.error("[Chat Debug] AI Task error: #{inspect(err)}")
            error_msg = %{
              type: :ai,
              content: "Sorry, I encountered an error while processing your request. Please try again.",
              timestamp: timestamp_now()
            }
            send(self_pid, {:bot_reply, error_msg, app_id})
        end
      end)
      
      {:noreply, socket}
    end
  end
end

  #########################
  #   LOGS HANDLERS       #
  #########################
  def handle_event("start_log_stream", _, socket) do
    app_id = socket.assigns.selected_app

    if app_id && !Map.get(socket.assigns.log_streams, app_id) do
      app = Enum.find(socket.assigns.apps, &(&1.id == app_id))

      if app do
        {:ok, stream_pid} = start_log_stream(socket.assigns.fly_token, app.name, self(), app_id)
        log_streams = Map.put(socket.assigns.log_streams, app_id, stream_pid)

        {:noreply,
         socket
         |> assign(:log_streams, log_streams)
         |> assign(:logs_loading, true)}
      else
        {:noreply, socket}
      end
    else
      {:noreply, socket}
    end
  end

  def handle_event("stop_log_stream", _, socket) do
    app_id = socket.assigns.selected_app

    if app_id && Map.get(socket.assigns.log_streams, app_id) do
      stream_pid = socket.assigns.log_streams[app_id]
      Process.exit(stream_pid, :normal)

      log_streams = Map.delete(socket.assigns.log_streams, app_id)

      {:noreply,
       socket
       |> assign(:log_streams, log_streams)
       |> assign(:logs_loading, false)}
    else
      {:noreply, socket}
    end
  end

  def handle_event("clear_logs", _, socket) do
    app_id = socket.assigns.selected_app
    logs = if app_id, do: Map.put(socket.assigns.logs, app_id, []), else: socket.assigns.logs
    {:noreply, assign(socket, :logs, logs)}
  end

# Build comprehensive app context for AI
defp build_app_context(app, metrics, logs) do
  # Format metrics data
  metrics_summary = case metrics do
    nil -> "No metrics available yet"
    {:error, reason} -> "Metrics error: #{reason}"
    metrics_list when is_list(metrics_list) ->
      metrics_list
      |> Enum.map(fn {label, result} ->
        case result do
          {:ok, []} -> "#{label}: No data available"
          {:ok, data} -> format_metrics_data(label, data)
          {:error, err} -> "#{label}: Error - #{err}"
        end
      end)
      |> Enum.join(", ")
    _ -> "Metrics loading or unavailable"
  end
  
  # Format recent logs
  logs_summary = case logs do
    nil -> "No logs available"
    [] -> "No recent logs"
    log_entries when is_list(log_entries) ->
      recent_logs = log_entries |> Enum.take(-5)
      log_summary = recent_logs
      |> Enum.map(fn log ->
        "#{log.timestamp} [#{log.level}]: #{String.slice(log.message, 0, 100)}"
      end)
      |> Enum.join("\n")
      
      "Recent logs (last 5 entries):\n#{log_summary}"
    _ -> "Logs unavailable"
  end
  
  %{
    app: app,
    metrics: metrics_summary,
    logs: logs_summary,
    timestamp: timestamp_now()
  }
end

# Format specific metrics data for AI context
defp format_metrics_data("Memory Usage (%)", data) do
  memory_values = data
  |> Enum.map(fn metric ->
    if metric["value"] && length(metric["value"]) >= 2 do
      case Float.parse(Enum.at(metric["value"], 1)) do
        {val, _} -> Float.round(val, 1)
        :error -> nil
      end
    else
      nil
    end
  end)
  |> Enum.filter(&(&1 != nil))
  
  case memory_values do
    [] -> "Memory Usage: No data"
    values -> 
      avg_memory = Enum.sum(values) / length(values)
      "Memory Usage: #{Float.round(avg_memory, 1)}% (avg of #{length(values)} readings)"
  end
end

defp format_metrics_data("CPU Usage", data) do
  cpu_values = data
  |> Enum.map(fn metric ->
    if metric["value"] && length(metric["value"]) >= 2 do
      case Float.parse(Enum.at(metric["value"], 1)) do
        {val, _} -> Float.round(val, 2)
        :error -> nil
      end
    else
      nil
    end
  end)
  |> Enum.filter(&(&1 != nil))
  
  case cpu_values do
    [] -> "CPU Usage: No data"
    values -> 
      avg_cpu = Enum.sum(values) / length(values)
      "CPU Usage: #{Float.round(avg_cpu, 2)}% (avg of #{length(values)} readings)"
  end
end

defp format_metrics_data("HTTP Responses (by status)", data) do
  status_counts = data
  |> Enum.map(fn metric ->
    status = get_in(metric, ["metric", "status"])
    value = if metric["value"] && length(metric["value"]) >= 2 do
      Enum.at(metric["value"], 1)
    else
      "0"
    end
    {status, value}
  end)
  |> Enum.filter(fn {status, _} -> status != nil end)
  |> Enum.map(fn {status, value} -> "#{status}: #{value}" end)
  |> Enum.join(", ")
  
  case status_counts do
    "" -> "HTTP Responses: No data"
    counts -> "HTTP Response Status Codes: #{counts}"
  end
end

defp format_metrics_data(label, _data), do: "#{label}: Available but not parsed"






  #########################
  #   ASYNC TASK HANDLERS #
  #########################

  # Handle async metrics task completion
  def handle_info({ref, metrics_result}, socket) when is_reference(ref) do
    case find_task_for_ref(socket.assigns.async_tasks, ref) do
      {app_id, _task} ->
        app_metrics = Map.put(socket.assigns.app_metrics, app_id, metrics_result)
        tasks = Map.delete(socket.assigns.async_tasks, app_id)
        metrics_loading = Map.delete(socket.assigns.metrics_loading, app_id)

        {:noreply,
         socket
         |> assign(:app_metrics, app_metrics)
         |> assign(:async_tasks, tasks)
         |> assign(:metrics_loading, metrics_loading)}

      nil ->
        {:noreply, socket}
    end
  end

  # Handle normal task shutdown
  def handle_info({:DOWN, _ref, :process, _pid, :normal}, socket), do: {:noreply, socket}

  # Handle task failures
  def handle_info({:DOWN, ref, :process, _pid, reason}, socket) do
    Logger.warning("Metrics fetch task failed: #{inspect(reason)}")

    case find_task_for_ref(socket.assigns.async_tasks, ref) do
      {app_id, _task} ->
        tasks = Map.delete(socket.assigns.async_tasks, app_id)
        metrics_loading = Map.delete(socket.assigns.metrics_loading, app_id)
        # Set error state for this app's metrics
        app_metrics = Map.put(socket.assigns.app_metrics, app_id, {:error, "Failed to load metrics"})

        {:noreply,
         socket
         |> assign(:async_tasks, tasks)
         |> assign(:metrics_loading, metrics_loading)
         |> assign(:app_metrics, app_metrics)}

      nil ->
        {:noreply, socket}
    end
  end

  def handle_info({:log_entry, app_id, log_entry}, socket) do
    current_logs = Map.get(socket.assigns.logs, app_id, [])
    updated_logs = (current_logs ++ [log_entry]) |> Enum.take(-1000)

    logs = Map.put(socket.assigns.logs, app_id, updated_logs)

    {:noreply,
     socket
     |> assign(:logs, logs)
     |> assign(:logs_loading, false)}
  end

  def handle_info({:log_stream_started, app_id}, socket) do
    Logger.info("Log stream started successfully for app: #{app_id}")
    {:noreply, assign(socket, :logs_loading, false)}
  end

  def handle_info({:log_stream_error, app_id, error}, socket) do
    Logger.warning("Log stream error for app #{app_id}: #{error}")

    log_streams = Map.delete(socket.assigns.log_streams, app_id)

    {:noreply,
     socket
     |> assign(:log_streams, log_streams)
     |> assign(:logs_loading, false)
     |> put_flash(:error, "Log stream error: #{error}")}
  end

 def handle_info({:bot_reply, ai_msg, app_id}, socket) do
  updated_messages = Map.update(socket.assigns.messages, app_id, [ai_msg], &(&1 ++ [ai_msg]))
  {:noreply, assign(socket, messages: updated_messages, is_typing: false)}
end


  #########################
  #   ASYNC HELPERS       #
  #########################

  defp async_fetch_metrics_for_app(socket, app_id) do
    apps = socket.assigns.apps
    app = Enum.find(apps, &(&1.id == app_id))

    if app && !Map.get(socket.assigns.async_tasks, app_id) do
      # Mark as loading
      metrics_loading = Map.put(socket.assigns.metrics_loading, app_id, true)

      # Start async task
      task = Task.async(fn ->
        try do
          FullstackChallenge.FlyMetrics.fetch_for_app(app.name)
        rescue
          error ->
            Logger.warning("Error fetching metrics for #{app.name}: #{inspect(error)}")
            {:error, "Metrics unavailable"}
        catch
          :exit, reason ->
            Logger.warning("Metrics fetch timeout for #{app.name}: #{inspect(reason)}")
            {:error, "Metrics timeout"}
        end
      end)

      # Store task reference
      tasks = Map.put(socket.assigns.async_tasks, app_id, task)

      socket
      |> assign(:async_tasks, tasks)
      |> assign(:metrics_loading, metrics_loading)
    else
      socket
    end
  end

  defp find_task_for_ref(tasks, ref) do
    Enum.find(tasks, fn {_app_id, task} ->
      task.ref == ref
    end)
  end

  #########################
  #   LOG STREAMING IMPL  #
  #########################
  defp start_log_stream(token, app_name, parent_pid, app_id) do
    pid = spawn_link(fn ->
      stream_logs_via_cli(token, app_name, parent_pid, app_id)
    end)
    {:ok, pid}
  end

  defp stream_logs_via_cli(token, app_name, parent_pid, app_id) do
    Logger.info("Starting log stream via CLI for app: #{app_name}")

    _env = [{"FLY_API_TOKEN", token}]
    cmd_args = ["logs", "--app", app_name, "--json"]

    try do
      port = Port.open(
        {:spawn_executable, System.find_executable("fly")},
        [
          :binary,
          :exit_status,
          {:args, cmd_args},
          # {:env, [{"FLY_API_TOKEN", token}]}
        ]
      )

      send(parent_pid, {:log_stream_started, app_id})
      receive_cli_logs(parent_pid, app_id, port)

    rescue
      error ->
        Logger.error("Failed to start fly logs command: #{inspect(error)}")
        send(parent_pid, {:log_stream_error, app_id, "CLI command failed: #{inspect(error)}"})
    end
  end

  defp receive_cli_logs(parent_pid, app_id, port) do
    receive do
      {^port, {:data, {:eol, line}}} ->
        handle_log_line(line, parent_pid, app_id)
        receive_cli_logs(parent_pid, app_id, port)

      {^port, {:data, {:noeol, _partial_line}}} ->
        receive_cli_logs(parent_pid, app_id, port)

      {^port, {:data, line}} when is_binary(line) ->
        handle_log_line(line, parent_pid, app_id)
        receive_cli_logs(parent_pid, app_id, port)

      {^port, {:exit_status, status}} ->
        Logger.info("Fly logs command exited with status: #{status}")
        send(parent_pid, {:log_stream_error, app_id, "Command exited with status #{status}"})

      other ->
        Logger.debug("Unexpected message from fly logs: #{inspect(other)}")
        receive_cli_logs(parent_pid, app_id, port)
    after
      60_000 ->
        Logger.info("Log stream timeout for app_id: #{app_id}")
        Port.close(port)
        send(parent_pid, {:log_stream_error, app_id, "Stream timeout"})
    end
  end

  defp handle_log_line(line, parent_pid, app_id) do
    case parse_fly_log_line(line) do
      {:ok, log_entry} ->
        send(parent_pid, {:log_entry, app_id, log_entry})

      {:error, _reason} ->
        log_entry = %{
          timestamp: timestamp_now(),
          level: "info",
          message: String.trim(line),
          instance: nil,
          raw: line
        }
        send(parent_pid, {:log_entry, app_id, log_entry})
    end
  end

  defp parse_fly_log_line(line) do
    try do
      case Jason.decode(String.trim(line)) do
        {:ok, %{"timestamp" => timestamp, "message" => message} = json} ->
          {:ok, %{
            timestamp: format_fly_timestamp(timestamp),
            level: Map.get(json, "level", "info"),
            message: message,
            instance: Map.get(json, "instance"),
            region: Map.get(json, "region"),
            raw: line
          }}
        {:ok, _json} ->
          {:error, "unexpected_json_structure"}
        {:error, _} ->
          {:error, "invalid_json"}
      end
    rescue
      _ ->
        {:error, "parse_error"}
    end
  end

  defp format_fly_timestamp(timestamp) when is_binary(timestamp) do
    case DateTime.from_iso8601(timestamp) do
      {:ok, dt, _} ->
        dt
        |> DateTime.shift_zone!("Etc/UTC")
        |> Calendar.strftime("%H:%M:%S")
      _ ->
        timestamp_now()
    end
  end
  defp format_fly_timestamp(_), do: timestamp_now()

  defp generate_bot_reply(user_msg, app, socket) do
    msg = String.downcase(user_msg)
    cond do
      msg =~ "health" ->
        app_struct = Enum.find(socket.assigns.discord_apps, &(&1.id == app))
        icon = app_status_icon(app_struct.status)
        "Health check for **#{app_struct.name}** #{icon} — All systems up!"
      msg =~ "error" or msg =~ "errors" ->
        if app == "worker-service" do
          "🔴 **Critical Error:** Worker process failure detected!\n\nCheck logs!"
        else
          "✅ No current critical errors."
        end
      msg =~ "slow" or msg =~ "performance" ->
        "📊 Current response time for #{app}: *randomly* fine!"
      true ->
        "Hey! I'm monitoring **#{app}**. Try commands like `health`, `error`, `slow`."
    end
  end

  #########################
  #     OPTIMIZED FLY.IO  #
  #########################
  defp load_apps(socket) do
    case list_apps(socket.assigns.fly_token) do
      {:ok, apps} ->
        apps = Enum.map(apps, fn app -> %{app | id: to_string(app.id)} end)

        real_ids = Enum.map(apps, & &1.id)
        selected_app =
          if socket.assigns.selected_app in real_ids do
            socket.assigns.selected_app
          else
            List.first(real_ids)
          end

        socket =
          socket
          |> assign(:apps, apps)
          |> assign(:filtered_apps, apps)  # Initialize filtered apps
          |> assign(:app_metrics, %{})
          |> assign(:selected_app, selected_app)
          |> assign(:loading, false)
          |> assign(:error, nil)

        # Only fetch metrics for selected app initially
        if selected_app do
          async_fetch_metrics_for_app(socket, selected_app)
        else
          socket
        end

      {:error, reason} ->
        socket
        |> assign(:loading, false)
        |> assign(:filtered_apps, [])  # Also initialize on error
        |> assign(:error, "Failed to load apps: #{reason}")
    end
  end

  defp list_apps(token) do
    if not valid_token_format?(token) do
      Logger.warning("Invalid token format: #{String.slice(token, 0, 8)}...")
      {:error, "Invalid token format"}
    end

    headers = [{"Authorization", "Bearer #{token}"}]
    Logger.info("Calling Fly.io GraphQL API to list apps...")

    case Req.post("https://api.fly.io/graphql",
           headers: headers,
           form: [query: "{ apps { nodes { id name status organization { slug } createdAt } } }"],
           connect_options: [timeout: 10_000],
           receive_timeout: 15_000
         ) do
      {:ok, %{status: 200, body: body}} ->
        Logger.info("Fly.io API Response received")
        apps = parse_apps_response(body)
        Logger.info("Parsed #{length(apps)} apps")
        {:ok, apps}
      {:ok, %{status: 401}} ->
        Logger.warning("Fly.io API returned 401 Unauthorized")
        {:error, "Invalid token"}
      {:ok, %{status: status, body: _body}} ->
        Logger.warning("Fly.io API returned status #{status}")
        {:error, "API error (#{status})"}
      {:error, %{reason: :timeout}} ->
        Logger.error("Fly.io API request timed out")
        {:error, "Request timeout - please check your connection"}
      {:error, reason} ->
        Logger.error("Network error calling Fly.io API: #{inspect(reason)}")
        {:error, "Network error"}
    end
  end

  # [Rest of the helper functions remain the same...]
  defp launch_app(token, name) do
    Logger.info("Attempting to launch app: #{name}")
    case get_user_organization(token) do
      {:ok, org_id} ->
        case create_app(token, name, org_id) do
          {:ok, _app_data} ->
            case allocate_ip_addresses(token, name) do
              {:ok, _ip_data} ->
                case deploy_nginx_app(token, name) do
                  {:ok, _machine_data} ->
                    Logger.info("Successfully launched app: #{name}")
                    {:ok, %{}}
                  {:error, reason} ->
                    Logger.warning("App created but deployment failed: #{reason}")
                    {:error, "App created but deployment failed: #{reason}"}
                end
              {:error, reason} ->
                Logger.warning("App created but IP allocation failed: #{reason}")
                {:error, "App created but IP allocation failed: #{reason}"}
            end
          {:error, reason} ->
            {:error, reason}
        end
      {:error, reason} ->
        {:error, "Failed to get organization: #{reason}"}
    end
  end

  defp create_app(token, name, org_id) do
    headers = [{"Authorization", "Bearer #{token}"}, {"Content-Type", "application/json"}]
    mutation = %{
      query: """
        mutation($input: CreateAppInput!) {
          createApp(input: $input) {
            app {
              id
              name
            }
          }
        }
      """,
      variables: %{
        input: %{
          name: name,
          organizationId: org_id
        }
      }
    }
    case Req.post("https://api.fly.io/graphql",
           headers: headers,
           body: Jason.encode!(mutation)
         ) do
      {:ok, %{status: 200, body: %{"data" => %{"createApp" => data}}}} when not is_nil(data) ->
        Logger.info("Created app: #{inspect(data)}")
        {:ok, data}
      {:ok, %{status: 200, body: %{"errors" => errors}}} ->
        Logger.warning("GraphQL errors creating app: #{inspect(errors)}")
        error_msg = get_in(errors, [Access.at(0), "message"]) || "GraphQL error"
        {:error, error_msg}
      {:ok, %{status: 401}} ->
        {:error, "Invalid token"}
      {:ok, %{status: status, body: body}} ->
        Logger.warning("Fly.io API returned status #{status} with body: #{inspect(body)}")
        {:error, "API error (#{status})"}
      {:error, reason} ->
        Logger.error("Network error creating app: #{inspect(reason)}")
        {:error, "Network error"}
    end
  end

defp allocate_ip_addresses(token, app_name) do
  headers = [
    {"Authorization", "Bearer #{token}"},
    {"Content-Type", "application/json"}
  ]

  ipv4_mutation = %{
    query: """
    mutation($input: AllocateIPAddressInput!) {
      allocateIpAddress(input: $input) {
        ipAddress {
          id
          address
          type
        }
      }
    }
    """,
    variables: %{
      input: %{
        appId: app_name,
        type: "v4"
      }
    }
  }

  case Req.post("https://api.fly.io/graphql",
         headers: headers,
         body: Jason.encode!(ipv4_mutation)
       ) do
    {:ok, %{status: 200, body: %{"data" => %{"allocateIpAddress" => ipv4_data}}}} when not is_nil(ipv4_data) ->
      Logger.info("Allocated IPv4 for app #{app_name}: #{inspect(ipv4_data)}")
      allocate_ipv6(token, app_name)
      {:ok, ipv4_data}

    {:ok, %{status: 200, body: %{"errors" => errors}}} ->
      Logger.warning("GraphQL errors allocating IP: #{inspect(errors)}")
      error_msg = get_in(errors, [Access.at(0), "message"]) || "IP allocation error"
      {:error, error_msg}

    {:ok, %{status: 401}} ->
      {:error, "Invalid token"}

    {:ok, %{status: status, body: body}} ->
      Logger.warning("IP allocation API returned status #{status} with body: #{inspect(body)}")
      {:error, "IP allocation failed (#{status})"}

    {:error, reason} ->
      Logger.error("Network error allocating IP: #{inspect(reason)}")
      {:error, "Network error"}
  end
end

defp allocate_ipv6(token, app_name) do
  headers = [
    {"Authorization", "Bearer #{token}"},
    {"Content-Type", "application/json"}
  ]

  ipv6_mutation = %{
    query: """
    mutation($input: AllocateIPAddressInput!) {
      allocateIpAddress(input: $input) {
        ipAddress {
          id
          address
          type
        }
      }
    }
    """,
    variables: %{
      input: %{
        appId: app_name,
        type: "v6"
      }
    }
  }

  case Req.post("https://api.fly.io/graphql",
         headers: headers,
         body: Jason.encode!(ipv6_mutation)
       ) do
    {:ok, %{status: 200, body: %{"data" => %{"allocateIpAddress" => ipv6_data}}}} when not is_nil(ipv6_data) ->
      Logger.info("Allocated IPv6 for app #{app_name}: #{inspect(ipv6_data)}")
      {:ok, ipv6_data}

    {:ok, %{status: 200, body: %{"errors" => _errors}}} ->
      Logger.info("IPv6 allocation failed for app #{app_name}, continuing with IPv4 only")
      {:ok, nil}

    _ ->
      Logger.info("IPv6 allocation failed for app #{app_name}, continuing with IPv4 only")
      {:ok, nil}
  end
end


  defp deploy_nginx_app(token, app_name) do
    headers = [{"Authorization", "Bearer #{token}"}, {"Content-Type", "application/json"}]
    template = FullstackChallenge.AppTemplates.nginx_app_template(app_name)
    machine_config = %{
      config: %{
        image: "nginx:alpine",
        env: %{},
        services: [
          %{
            ports: [
              %{
                port: 80,
                handlers: ["http"]
              },
              %{
                port: 443,
                handlers: ["tls", "http"]
              }
            ],
            protocol: "tcp",
            internal_port: 8080
          }
        ],
        files: [
          %{
            guest_path: "/usr/share/nginx/html/index.html",
            raw_value: Base.encode64(template.index_html)
          },
          %{
            guest_path: "/etc/nginx/nginx.conf",
            raw_value: Base.encode64(template.nginx_conf)
          }
        ],
        guest: %{
          cpu_kind: "shared",
          cpus: 1,
          memory_mb: 256
        }
      }
    }
    case Req.post("https://api.machines.dev/v1/apps/#{app_name}/machines",
           headers: headers,
           body: Jason.encode!(machine_config)
         ) do
      {:ok, %{status: status, body: body}} when status in [200, 201] ->
        Logger.info("Deployed machine for app #{app_name}: #{inspect(body)}")
        {:ok, body}
      {:ok, %{status: 401}} ->
        {:error, "Invalid token"}
      {:ok, %{status: status, body: body}} ->
        Logger.warning("Machines API returned status #{status} with body: #{inspect(body)}")
        {:error, "Deployment failed (#{status})"}
      {:error, reason} ->
        Logger.error("Network error deploying app: #{inspect(reason)}")
        {:error, "Network error"}
    end
  end

  defp get_user_organization(token) do
    headers = [{"Authorization", "Bearer #{token}"}, {"Content-Type", "application/json"}]
    query = %{
      query: """
        {
          viewer {
            organizations {
              nodes {
                id
                slug
              }
            }
          }
        }
      """
    }
    case Req.post("https://api.fly.io/graphql",
           headers: headers,
           body: Jason.encode!(query)
         ) do
      {:ok, %{status: 200, body: %{"data" => %{"viewer" => %{"organizations" => %{"nodes" => [_ | _] = orgs}}}}}} ->
        org_id = get_in(orgs, [Access.at(0), "id"])
        {:ok, org_id}
      {:ok, %{status: 200, body: %{"errors" => errors}}} ->
        Logger.warning("GraphQL errors getting organization: #{inspect(errors)}")
        {:error, "Failed to get organization"}
      {:ok, %{status: status, body: body}} ->
        Logger.warning("Failed to get organization, status #{status}: #{inspect(body)}")
        {:error, "API error"}
      {:error, reason} ->
        Logger.error("Network error getting organization: #{inspect(reason)}")
        {:error, "Network error"}
    end
  end

  defp destroy_app(token, app_name) do
    headers = [{"Authorization", "Bearer #{token}"}, {"Content-Type", "application/json"}]
    Logger.info(
      "Attempting to destroy app: #{app_name} with token: #{String.slice(token, 0, 8)}..."
    )
    mutation = %{
      query: """
        mutation($appId: ID!) {
          deleteApp(appId: $appId) {
            organization {
              id
            }
          }
        }
      """,
      variables: %{
        appId: app_name
      }
    }
    case Req.post("https://api.fly.io/graphql",
           headers: headers,
           body: Jason.encode!(mutation)
         ) do
      {:ok, %{status: 200, body: %{"data" => %{"deleteApp" => data}}}} when not is_nil(data) ->
        Logger.info("Destroy app API response (data): #{inspect(data)}")
        {:ok, %{}}
      {:ok, %{status: 200, body: %{"errors" => errors}}} ->
        Logger.warning("GraphQL errors in destroy app: #{inspect(errors)}")
        error_msg = get_in(errors, [Access.at(0), "message"]) || "GraphQL error"
        {:error, error_msg}
      {:ok, %{status: 401, body: body}} ->
        Logger.warning("Destroy app unauthorized: #{inspect(body)}")
        {:error, "Invalid token"}
      {:ok, %{status: 404, body: body}} ->
        Logger.warning("Destroy app not found: #{inspect(body)}")
        {:error, "App not found"}
      {:ok, %{status: status, body: body}} ->
        Logger.warning("Fly.io API returned status #{status} with body: #{inspect(body)}")
        {:error, "API error (#{status})"}
      {:error, reason} ->
        Logger.error("Network error destroying app: #{inspect(reason)}")
        {:error, "Network error"}
    end
  end

  defp parse_apps_response(%{"errors" => errors}) when is_list(errors) do
    Logger.warning("GraphQL errors in parse_apps_response: #{inspect(errors)}")
    []
  end
  defp parse_apps_response(%{"data" => %{"apps" => %{"nodes" => apps}}}) when is_list(apps) do
    Enum.map(apps, fn app ->
      %{
        id: Map.get(app, "id", Map.get(app, "name", "unknown")),
        name: Map.get(app, "name", "unknown"),
        status: Map.get(app, "status", "running"),
        region: Map.get(app["organization"], "slug", "unknown"),
        created_at: Map.get(app, "createdAt", "unknown"),
        type: "web"
      }
    end)
  end

  defp valid_token_format?(token) when is_binary(token) do
    String.starts_with?(token, "FlyV1") and String.length(token) > 50
  end
  defp valid_token_format?(_), do: false

  defp get_token_from_session(session) do
    case Map.get(session, "auth_token_ref") do
      ref when is_binary(ref) ->
        session_id = Map.get(session, "session_id") || generate_session_id()
        case FullstackChallenge.TokenStore.get_token(ref, session_id) do
          {:ok, token} ->
            token
          {:error, reason} ->
            Logger.debug("Token retrieval failed: #{reason}")
            try_fallback_methods(session)
        end
      nil ->
        try_fallback_methods(session)
    end
  end

  defp try_fallback_methods(session) do
    case FullstackChallenge.TokenSecurity.decrypt_token(Map.get(session, "encrypted_fly_token")) do
      {:ok, token} ->
        token
      _ ->
        case Map.get(session, "auth_token") do
          token when is_binary(token) ->
            token
          _ ->
            FullstackChallenge.EnvConfig.get_fly_token()
        end
    end
  end

  defp generate_session_id do
    :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)
  end

  #########################
  #     UI HELPERS        #
  #########################
  defp app_icon("web"), do: "🌐"
  defp app_icon("api"), do: "⚡"
  defp app_icon("worker"), do: "⚙️"
  defp app_icon(_), do: "#"

  defp app_status_icon("deployed"), do: "🟢"
  defp app_status_icon("pending"), do: "🟡"
  defp app_status_icon("suspended"), do: "🔴"
  defp app_status_icon(_), do: "⚪"

  defp timestamp_now do
    t = Time.utc_now()
    "#{pad2(t.hour)}:#{pad2(t.minute)}"
  end

defp openrouter_chat_api(app_context, message_history) do
  api_key = System.get_env("OPENROUTER_API_KEY")
  
  if is_nil(api_key) or String.trim(api_key) == "" do
    Logger.error("[Chat Debug] OPENROUTER_API_KEY not set")
    {:error, "API key not configured"}
  else
    model = "openai/gpt-oss-20b:free"  # More reliable model
    
    # Build system message with comprehensive app context
    system_message = build_system_message(app_context)
    
    # Convert message history to OpenAI format
    api_messages = [
      %{role: "system", content: system_message}
    ] ++ convert_messages_to_api_format(message_history)
    
    body = %{
      model: model,
      messages: api_messages,
      max_tokens: 500,
      temperature: 0.7
    } |> Jason.encode!()
    
    headers = [
      {"Authorization", "Bearer #{api_key}"},
      {"Content-Type", "application/json"},
      {"HTTP-Referer", "https://yourapp.com"},
      {"X-Title", "Fly.io Monitoring Assistant"}
    ]
    
    url = "https://openrouter.ai/api/v1/chat/completions"
    
    Logger.info("[Chat Debug] Making API call to OpenRouter with #{length(api_messages)} messages")
    
    case HTTPoison.post(url, body, headers, recv_timeout: 30_000, timeout: 30_000) do
      {:ok, %HTTPoison.Response{status_code: 200, body: resp_body}} ->
        Logger.info("[Chat Debug] Response received from OpenRouter")
        case Jason.decode(resp_body) do
          {:ok, %{"choices" => [%{"message" => %{"content" => reply}} | _]}} ->
            Logger.info("[Chat Debug] Successfully parsed AI response")
            {:ok, reply}
          {:ok, %{"error" => error_info}} ->
            Logger.error("[Chat Debug] OpenRouter API error: #{inspect(error_info)}")
            {:error, "API error: #{error_info["message"] || "Unknown error"}"}
          {:ok, unexpected} ->
            Logger.error("[Chat Debug] Unexpected response format: #{inspect(unexpected)}")
            {:error, "Unexpected response format"}
          {:error, json_error} ->
            Logger.error("[Chat Debug] JSON parse error: #{inspect(json_error)}")
            {:error, "Response parsing failed"}
        end
      
      {:ok, %HTTPoison.Response{status_code: 401}} ->
        Logger.error("[Chat Debug] Authentication failed - check API key")
        {:error, "Authentication failed - please check API key"}
      
      {:ok, %HTTPoison.Response{status_code: status_code, body: resp_body}} ->
        Logger.error("[Chat Debug] HTTP error #{status_code}: #{resp_body}")
        {:error, "API returned error #{status_code}"}
      
      {:error, %HTTPoison.Error{reason: :timeout}} ->
        Logger.error("[Chat Debug] Request timeout")
        {:error, "Request timeout - please try again"}
      
      {:error, %HTTPoison.Error{reason: reason}} ->
        Logger.error("[Chat Debug] HTTP client error: #{inspect(reason)}")
        {:error, "Network error: #{inspect(reason)}"}
      
      other ->
        Logger.error("[Chat Debug] Unexpected response: #{inspect(other)}")
        {:error, "Unexpected error occurred"}
    end
  end
end

# Build comprehensive system message for AI
defp build_system_message(app_context) do
  app = app_context.app
  
  """
  You are an AI monitoring assistant for Fly.io applications. You help developers understand their app's health, performance, and issues.

  CURRENT APP CONTEXT:
  - App Name: #{app.name}
  - App ID: #{app.id}  
  - Status: #{app.status}
  - Type: #{app.type}
  - Region: #{app.region || "unknown"}
  - Created: #{app.created_at || "unknown"}

  METRICS DATA:
  #{app_context.metrics}

  LOG DATA:
  #{app_context.logs}

  INSTRUCTIONS:
  - Provide helpful, technical insights about the app's health and performance
  - Answer questions about metrics, logs, status, and deployment issues
  - Suggest troubleshooting steps when problems are detected
  - Be concise but informative
  - Use the actual data provided above in your responses
  - If metrics show issues (high CPU/memory, errors), proactively mention them
  - Format responses clearly with markdown when helpful

  Current timestamp: #{app_context.timestamp}
  """
end

# Convert internal message format to OpenAI API format
defp convert_messages_to_api_format(messages) do
  messages
  |> Enum.map(fn msg ->
    role = case msg.type do
      :user -> "user"
      :ai -> "assistant"
      _ -> "user"
    end
    %{role: role, content: msg.content}
  end)
end


  defp pad2(n) when is_integer(n), do: if(n < 10, do: "0#{n}", else: "#{n}")
end
