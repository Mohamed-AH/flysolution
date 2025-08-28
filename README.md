# Fly.io Full Stack Phoenix Challenge

This app is a barebones Fly.io dashboard. It lists apps, lets you launch a new app, and allows you to destroy an app.

You can't do a whole lot with it at the moment, but that's where you come in.

## The challenge

In the pre-work exercise for this role, we asked you what the UX should be for delivering logs or metrics for Fly apps. Now we want you to implement what you think would work best for our customers.

You can follow up on some of what you described in the pre-work, or you can start from scratch with a new idea. Pick one, logs or metrics, and run with it. Show us the first thing you'd ship to users.

We don't have a public API for getting logs, but we do have one for [metrics](https://fly.io/docs/monitoring/metrics/). Just because we don't have a public API for logs doesn't mean you can't get them. You'll need to figure out how to pull that data and make it available within the UI.

"Logs or metrics" is a pretty big topic, and that's intentional. Show us how you scope work. Show us how ruthless you can be while still delivering significant value to users. Wow us.

## Requirements:

- We're not timing you, but this should take a couple hours, not days. Scope your work accordingly. What is the smallest useful thing, the best first thing, you can ship?
- We love a coherent UX over a pretty UI any day of the week.
- What would you do in further iterations? Tell us about it in notes in the project. Tell us about the tradeoffs you felt you had to make.
- We can run your app locally just by calling `mix setup && mix phx.server`. Better yet, we can deploy it and run it successfully.
- We will not evaluate your tests, but we will scrutinize your code.
- We can't offer much help or answer a lot questions. A big part of full stack work at Fly is piecing things together from many unknowns, and we want to see how you handle that. By all means, you can definitely ask questions, but we might respond with "That's part of the challenge 🙂". You'll never get dinged for asking questions though!
- You can use an LLM to help you with any part of this. We've run this challenge through an LLM. Your mileage may vary from ours, but the bar for this challenge is higher than what we've gotten most mainstream LLMs to cough up.
- We're expecting human effort here from you too. We'll give you human effort back: humans will evaluate what you produce using a rubric, not LLMs or automated testing frameworks.

## To start your Phoenix server

* Run `mix setup` to install and setup dependencies
* Start the Phoenix server with `mix phx.server` or inside IEx with `iex -S mix phx.server`

Now you can visit [`localhost:4000`](http://localhost:4000) from your browser.

## Things you might want to do first

- Create a Fly.io account if you don't already have one.
- Create an org-scoped token to go along with it: `flyctl tokens create org -o personal`
- Add that token to your `.env` file.
- Add credits to your account using the link we emailed you.

> [!TIP]
> Please note that the org slug you'll need for a Prometheus query is not "personal". Instead, you can find it by going to your billing page in the dashboard and checking the url, where you'll see something like `https://fly.io/dashboard/joe-smith-123/billing`. In that example, the org slug is `joe-smith-123`.

> [!IMPORTANT]
> We'll give you credits to burn so you don't have to worry about losing money here. You should have already received a link in the email we sent you about this challenge. If you have any trouble, just email us and let us know and we'll get you moving. Likewise, if you prefer to use a different org than your `personal` org, just create the new org and let us know. We'll add the credits directly.
