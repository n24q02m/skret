Output demo.gif

Require skret

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 700
Set TypingSpeed 80ms
Set PlaybackSpeed 1.0
Set Theme "Catppuccin Mocha"
Set Padding 20
Set WindowBar Colorful

Hide
Type "export PS1='$ '" Enter
Type "clear" Enter
Type "alias skret='skret'" Enter
Show

Sleep 1s

# --- Initialize a skret.yaml with local provider -----------------------------
Type "# Initialize a new skret project (local provider, no cloud needed)"
Enter
Sleep 1s
Type "skret init --provider=local"
Enter
Sleep 2s

# --- Set a few secrets --------------------------------------------------------
Type "# Set secrets"
Enter
Type "skret set DATABASE_URL 'postgres://user:pass@localhost/db'"
Enter
Sleep 1s
Type "skret set API_KEY 'sk-1234567890abcdef'"
Enter
Sleep 1s
Type "skret set FEATURE_FLAG 'enabled'"
Enter
Sleep 1s

# --- List them (values masked) ------------------------------------------------
Type "# List secrets — values masked by default"
Enter
Type "skret list"
Enter
Sleep 2s

# --- Inject into a command ----------------------------------------------------
Type "# Inject secrets as env vars into any command"
Enter
Type "skret run -- bash -c 'echo API_KEY=$API_KEY'"
Enter
Sleep 2s

# --- Export dotenv ------------------------------------------------------------
Type "# Export to .env for local dev"
Enter
Type "skret env --format=dotenv | head -3"
Enter
Sleep 2s

# --- Wrap up -----------------------------------------------------------------
Type "# One binary. Zero server. Zero subscription."
Enter
Sleep 2s
