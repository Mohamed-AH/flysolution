# Fly.io Dashboard Challenge: AI-First Incident Response

This project is my solution to the Fly.io dashboard challenge. Instead of building another traditional monitoring dashboard, I focused on a real-world problem: helping the exhausted developer who just wants to fix their app and go to bed. My solution is an AI-first approach to incident response that skips the learning curve of complex UIs.

The core idea is to create a "magic moment" where a developer can type "something's wrong" and get a direct, intuitive diagnosis. This is achieved by actively fetching real-time metrics and logs and feeding them to an AI model, which then provides a conversational and actionable response. The ability to collect and display this crucial information is the foundation of the app's value.

## Technical Overview

I used LiveView to build a single-page dashboard with real-time updates. The chat assistant is a simple state machine using a GenServer, and it leverages FlyMetrics to get health data. The conversational assistant is currently powered by a free chat model on OpenRouter.

The application's core function is to fetch and display real-time metrics and logs from Fly.io, which are then used as context for the AI model.

## Future Roadmap

This project is a multi-stage effort designed to scale with improvements in AI:

- **Basic Incident Chat (Current)**  
  Provides real-time, natural-language incident information.

- **Historical Context and Proactive Alerts**  
  The assistant will learn an app’s normal behavior and proactively suggest troubleshooting steps based on deployment history.

- **Action Suggestions**  
  The assistant will be able to suggest concrete, actionable fixes, like rolling back a deploy or adjusting a database connection pool.

For future versions, we could enhance this with an agentic AI architecture using tools like Flowise and a Pinecone vector database, trained on relevant data to provide higher value.

## Setup

To get the app running, you will need an OpenRouter API key in addition to the Fly API token and the ORG_SLUG. You can add these as environment variables in a `.env` file.

To start the Phoenix server:

1. Run `mix setup` to install dependencies.  
2. Start the server with `mix phx.server` or `iex -S mix phx.server`.
