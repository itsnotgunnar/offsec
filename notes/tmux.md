## Tmux Tips & Tricks

```bash                                                                                                                                                                                                                                     
tmux new -s {session name} # Create a new session
tmux ls # List the tmux sessions
tmux attach -t {session name} # Attach (go into) a tmux session
Prefix + d # Detach
Ctrl + b # Prefix key
Ctrl + r # Search through your past commands
Prefix + c # For a new window
Prefix + 0 (or 1,2,3,..) # Switch to that shell
tmux kill-session -t # Kill Session
prefix + % # Split window vertically
prefix + “ # Split window horizontally
Prefix + arrow keys # Switch panes interactively
Prefix + q # Display pane numbers
Prefix + q + number # Switch pane
Prefix + Ctrl + arrow keys # Adjust pane size
Prefix + Alt + 4 # Pre-made pane layout
Prefix + , # Rename window
Prefix + w  # Overview of session
Prefix + [ -> space + direction + Enter # Copy
Prefix + ] # Paste (You may need to ":set paste" in vi)
Prefix + [ + / # Search down
Prefix + [ + ? # Search up
Ctrl-B + X # Kill pane
# lowercase g # Go all the way to the top
# uppercase G # Go all the way to the bottom
```

To paste terminal contents to a normal file:
- Copy the text: select the text and press mouse left-button with shift key press too.
- Paste the text with shift key + middle-button

#### Tmux Logging

```bash
prefix + shift + p # Toggle (start/stop) logging in the current pane
prefix + alt + p # Save visible text, in the current pane. Equivalent of a "textual screenshot"
prefix + alt + shift + p # Save complete pane history to a file. Convenient if you retroactively remember you need to log/save all the work
prefix + alt + c # Clear pane history
prefix + I # Fetch and source plugin:
set -g mouse on
```
