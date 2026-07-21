# VHS tape for the README demo GIF (https://github.com/charmbracelet/vhs).
# Regenerate with:  go build -o netdoc . && vhs demo.tape
# Needs a working network connection; probes run live against github.com:443.

Output assets/demo.gif

Set FontSize 15
Set Width 1000
Set Height 650
Set Padding 12
Set TypingSpeed 40ms

Type "./netdoc github.com:443"
Sleep 500ms
Enter

# Let the probe chain complete and the verdict banner settle.
Sleep 5s

# Walk the checks so the detail pane changes.
Down@700ms 4
Sleep 1.5s
Down@700ms 3
Sleep 1.5s

# Launch a slow traceroute; it streams hops into the job pane.
Type "t"
Sleep 2.5s

# Start mtr while the traceroute is still running — now two live jobs.
Type "m"
Sleep 2s

# Tab between the two concurrent jobs while both stream.
Tab
Sleep 3s
Tab
Sleep 4s
